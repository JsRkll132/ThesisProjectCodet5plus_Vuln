import os
import asyncio
import aiohttp
import base64
import json
from aiolimiter import AsyncLimiter
from dotenv import load_dotenv
import time

# Cargar las variables de entorno
load_dotenv()

api_url_commits = "https://api.github.com/search/commits"
gh_apikey = os.getenv('TOKEN_GITHUB')

# Palabras clave y prefijos para las consultas
keywords =  [
    "sql injection", 
]

prefixes = [
    "vulnerable",
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
"""
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
"""


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
            #save_to_json(vuln_code, fixed_code, file_type, commit_url, file_path, k, p)
            pass

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
# Procesar los resultados asíncronamente por lotes, respetando el rate limit
github_rate_limiter = AsyncLimiter(25, 60)  # Máximo 30 solicitudes por minuto

# Crear un semáforo para limitar el número de tareas que se ejescutan simultáneamente
semaphore = asyncio.Semaphore(25)  # Limitar a 10 tareas en paralelo

# Función para esperar hasta que el rate limit se reinicie y reintentar
async def execute_search_commit_request(session, params):
    while True:
        async with session.get(api_url_commits, headers={"Authorization": f"Bearer {gh_apikey}"}, params=params) as response:
            if response.status == 200:
                print(200)
                data = await response.json()
                items = data.get('items', [])
                if not items:
                    print(f"No hay más resultados en la página .Terminando búsqueda.")
                    return []
                return items
            elif response.status == 403:  # Rate limit alcanzado
                print("Límite de búsqueda alcanzado. Esperando...")
                search_limit, search_reset, _, _ = await check_rate_limit(session)
                await sleep_until_reset(search_reset)  # Esperar hasta que se reinicie el rate limit
                # Reintentar después de que el límite se reinicie
            else:
                print(f"Error en la búsqueda de commits: {response.status}")
                return None


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

# Procesar los resultados asíncronamente por lotes, respetando el rate limit
async def run_tasks_in_batches(session, tasks):
    total_results_per_task = []
    
    for batch in asyncio.as_completed(tasks, timeout=None):
        result = await batch
        total_results_per_task.extend(result)
        await asyncio.sleep(1)
         # Pausar 1 segundo entre lotes para respetar el rate limit

    return total_results_per_task
def save_to_json(data, filename="commits_results.json"):
    try:
        with open(filename, 'w') as file:
            json.dump(data, file, indent=4)
        print(f"Datos guardados exitosamente en {filename}")
    except Exception as e:
        print(f"Error al guardar en archivo JSON: {e}")
# Función principal
async def main_():
    async with aiohttp.ClientSession() as session:
        search_tasks = []
        
        for k in keywords:
            for p in prefixes:
                query = f"{k}+{p}"
                print(f"process search for: {query}")
                search_tasks.extend(await search_commits(session, query))

        print(f"Total tareas creadas: {len(search_tasks)}")
        # Ejecutar las tareas en lotes respetando el rate limit
        all_commits_executed = await run_tasks_in_batches(session, search_tasks)
        print(all_commits_executed)
        # Procesar las respuestas
        save_to_json(all_commits_executed)
        """
        for response in all_commits_executed:
            if response:
                try:
                    if response.status == 200:
                        data = await response.json()
                        # Procesa los datos de los commits obtenidos
                except Exception as e:
                    print(f"Error al procesar la respuesta: {e}")"""

if __name__ == "__main__":
    asyncio.run(main_())