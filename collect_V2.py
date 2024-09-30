import os
import asyncio
import aiohttp
import base64
import json
from dotenv import load_dotenv
import time

# Cargar las variables de entorno
load_dotenv()

api_url_commits = "https://api.github.com/search/commits"
gh_apikey = os.getenv('TOKEN_GITHUB')

# Palabras clave y prefijos para las consultas
keywords = [
    "sql injection", 
    # (otros keywords)
]

prefixes = [
    "vulnerable", "fix", "attack", "correct", "malicious", 
    # (otros prefixes)
]

# Función para verificar la tasa de búsqueda y otras restricciones
async def check_rate_limit(session):
    async with session.get("https://api.github.com/rate_limit", headers={
        "Authorization": f"Bearer {gh_apikey}"
    }) as response:
        data = await response.json()
        search_limit = data['resources']['search']['remaining']
        search_reset = data['resources']['search']['reset']
        core_limit = data['resources']['core']['remaining']
        core_reset = data['resources']['core']['reset']
        return search_limit, search_reset, core_limit, core_reset

# Dormir hasta que se reinicie el límite
async def sleep_until_reset(reset_time):
    current_time = int(time.time())
    sleep_duration = reset_time - current_time
    if sleep_duration > 0:
        print(f"Esperando {sleep_duration / 60:.2f} minutos para reiniciar la tasa...")
        await asyncio.sleep(sleep_duration + 1)

# Obtener los archivos modificados de un commit específico
async def get_commit_files(session, owner, repo, sha):
    commit_url = f"https://api.github.com/repos/{owner}/{repo}/commits/{sha}"
    async with session.get(commit_url, headers={"Authorization": f"Bearer {gh_apikey}"}) as response:
        if response.status == 200:
            commit_data = await response.json()
            return commit_data.get('files', [])
        else:
            print(f"Error al obtener los archivos del commit: {response.status}")
            return []

# Obtener el contenido de un archivo en un commit específico
async def get_file_content(session, owner, repo, file_path, ref):
    file_url = f"https://api.github.com/repos/{owner}/{repo}/contents/{file_path}?ref={ref}"
    async with session.get(file_url, headers={"Authorization": f"Bearer {gh_apikey}"}) as response:
        if response.status == 200:
            file_data = await response.json()
            file_content = base64.b64decode(file_data['content']).decode('utf-8')
            return file_content
        else:
            print(f"Error al obtener el archivo: {response.status}")
            return None

# Guardar el código vulnerable y corregido en un archivo JSON en la carpeta correspondiente
def save_to_json(vuln_code, fixed_code, file_type, commit_url, file_path, keyword, prefix):
    data = {
        "vuln_code": vuln_code,
        "fixed_code": fixed_code,
        "file_type": file_type,
        "commit_url": commit_url,
        "file_path": file_path
    }
    
    folder_path = f"vulnerabilities_cv2/{keyword}/{prefix}"
    if not os.path.exists(folder_path):
        os.makedirs(folder_path)
    
    json_file_name = f"{folder_path}/{file_path.replace('/', '_')}.json"
    
    try:
        with open(json_file_name, "w") as json_file:
            json.dump(data, json_file, indent=4)
        print(f"Guardado exitosamente en {json_file_name}")
    except Exception as e:
        print(f"Error al guardar el archivo JSON: {e}")



# Función para procesar archivos de los commits
async def process_commit_files(session, commit, k, p):
    sha = commit['sha']
    commit_url = commit['html_url']
    repo_info = commit['repository']
    owner = repo_info['owner']['login']
    repo = repo_info['name']

    files = await get_commit_files(session, owner, repo, sha)
    for file in files:
        file_path = file['filename']
        file_type = os.path.splitext(file_path)[-1]
        previous_sha = commit['parents'][0]['sha']

        vuln_code = await get_file_content(session, owner, repo, file_path, previous_sha)
        fixed_code = await get_file_content(session, owner, repo, file_path, sha)

        if vuln_code and fixed_code:
            save_to_json(vuln_code, fixed_code, file_type, commit_url, file_path, k, p)


# Obtener el tamaño de lote dinámico basado en el rate limit
async def get_batch_size(session, limit_type):
    search_limit, search_reset, core_limit, core_reset = await check_rate_limit(session)
    return search_limit if limit_type == "search" else core_limit

# Procesar los commits y archivos respetando el rate limit en batches
async def process_search_and_files(session, query, k, p):
    commits = await search_commits(session, query)
    await run_tasks_in_batches(session, [process_commit_files(session, commit, k, p) for commit in commits], limit_type="core")

# Función principal
async def main():
    async with aiohttp.ClientSession() as session:
        search_tasks = []
        for k in keywords:
            for p in prefixes:
                query = f"{k}+{p}"
                search_tasks.append(process_search_and_files(session, query, k, p))
        
        await run_tasks_in_batches(session, search_tasks, limit_type="search")
# Función para buscar commits

# Procesar los resultados asíncronamente por lotes, respetando el rate limit
async def run_tasks_in_batches(session, tasks, limit_type):
    batch_size = await get_batch_size(session, limit_type)
    total_results_per_task = []
    
    # Ejecutar las tareas en lotes según el batch_size (rate limit)
    for i in range(0, len(tasks), batch_size):
        batch = tasks[i:i + batch_size]
        data = await asyncio.gather(*batch)
        total_results_per_task.extend(data)
        
        # Verificar si el límite de tasa se ha alcanzado
        search_limit, search_reset, core_limit, core_reset = await check_rate_limit(session)
        if limit_type == "search" and search_limit <= 0:
            await sleep_until_reset(search_reset)
        if limit_type == "core" and core_limit <= 0:
            await sleep_until_reset(core_reset)

    return total_results_per_task

# Función que realiza la búsqueda de commits pero crea las tareas sin ejecutarlas
async def execute_search_commit_request(session, params):
    return await session.get(api_url_commits, headers={"Authorization": f"Bearer {gh_apikey}"}, params=params)

# Crear las tareas sin ejecutarlas inmediatamente
async def search_commits(session, query, page=1, per_page=100, max_page=10):
    tasks = []
    while page <= max_page:
        params = {'q': query, 'per_page': per_page, 'page': page}
        print(params)
        
        # Crear tarea y agregarla a la lista (pero no la ejecutamos aún)
        task = asyncio.create_task(execute_search_commit_request(session, params))
        tasks.append(task)
        page += 1
    return tasks

# Crear las tareas para la búsqueda de commits
async def process_search_and_files_(session, query, k, p):
    print(f'process search for  : {query}')
    return await search_commits(session, query)

# Función principal
async def main_():
   async with aiohttp.ClientSession() as session:
        search_tasks = []
        
        # Crear todas las tareas pero no ejecutarlas aún
        for k in keywords:
            for p in prefixes:
                query = f"{k}+{p}"
                print(query)
                search_tasks.extend(await process_search_and_files_(session, query, k, p))
                print(f"Total tareas creadas: {len(search_tasks)}")

        # Ejecutar las tareas en lotes respetando el rate limit
        all_commits_executed = await run_tasks_in_batches(session, search_tasks, limit_type="search")
        
        print(all_commits_executed)
        for response in all_commits_executed : 
            if response.status == 200:
                data = await response.json()
                items = data.get('items', [])    
                print(f'items len {len(items)}')
                
        print(len(all_commits_executed))
if __name__ == "__main__":
    asyncio.run(main_())
