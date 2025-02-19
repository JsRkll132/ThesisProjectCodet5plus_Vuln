import os
import asyncio
import aiohttp
import base64
import json
from aiolimiter import AsyncLimiter
from dotenv import load_dotenv
import time
from itertools import cycle
# Cargar las variables de entorno
load_dotenv()

api_url_commits = "https://api.github.com/search/commits"
gh_apikey = os.getenv('TOKEN_GITHUB')
github_tokens = [
    os.getenv('TOKEN_GITHUB'),
    os.getenv('TOKEN_GITHUB_2'),
    os.getenv('TOKEN_GITHUB_3'),
    os.getenv('TOKEN_GITHUB_4'),
    os.getenv('TOKEN_GITHUB_5'),
    os.getenv('TOKEN_GITHUB_6'),
    os.getenv('TOKEN_GITHUB_7'),
    os.getenv('will')]
# Palabras clave y prefijos para las consultas
"""
keywords = [
    "sql injection", "unauthorised", "directory traversal", "rce", 
    "buffer overflow", "denial of service", "dos", "XXE", "vuln", "CVE", 
    "XSS", "NVD", "malicious", "cross site", "exploit", "remote code execution", 
    "XSRF", "cross site request forgery", "click jack", "clickjack", 
    "session fixation", "cross origin", "infinite loop", "brute force", 
    "cache overflow", "command injection", "cross frame scripting", "csv injection", 
    "eval injection", "execution after redirect", "format string", 
    "path disclosure", "function injection", "replay attack", 
    "session hijacking", "smurf","unauthorized" , "flooding", "tampering", 
    "sanitize", "sanitise"
]"""

keywords = [
    "ssrf","server side request forgery"
]

prefixes = [
    "vulnerable", "fix", "attack", "correct", "malicious", 
    "insecure", "vulnerability", "prevent", "protect", "issue", 
    "update", "improve", "change", "check"
]

# Función para verificar la tasa de búsqueda y otras restricciones
async def check_rate_limit(session):
    global current_token
    async with session.get("https://api.github.com/rate_limit", headers={
        "Authorization": f"Bearer {current_token}"
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
token_cycle = cycle(github_tokens)
def get_next_token():
    return next(token_cycle)
current_token = get_next_token()
# Función para esperar hasta que el rate limit se reinicie y reintentar
async def execute_search_commit_request(session, params):
    global current_token
    while True:
        try : 
            async with session.get(api_url_commits, headers={"Authorization": f"Bearer {current_token}"}, params=params,timeout=aiohttp.ClientTimeout(total=60)) as response:
                if response.status == 200:
                    print("200 OK")
                    data = await response.json()
                    items = data.get('items', [])
                    params_ = params['q'].split('+')
                    for item in items : 
                        item['keyword'] =  params_[0]
                        item['prefix'] =  params_[1]      
                    return items 
                elif response.status == 429 or response.status== 403:
                    current_token = get_next_token()
                    
                    error_data = await response.json()
                    if "secondary rate limit" in error_data.get('message', '').lower():
                        print("Límite secundario alcanzado. Esperando 1 minutos...")
                        await asyncio.sleep(6)  # Espera de 5 minutos antes de reintentar
                    else:
                        
                        search_limit, search_reset, _, _ = await check_rate_limit(session)
                        if search_limit == 0 : 
                            print("Límite de búsqueda alcanzado. Esperando...")
                            await sleep_until_reset(search_reset)
                else:
                    print(f"Error {response.status} en la búsqueda de commits.")
                    return None
        except Exception as e : 
            print(f"Error de conexión: {e}") 
            await asyncio.sleep(5)


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
    task = 0
    for batch in asyncio.as_completed(tasks, timeout=None):
        result = await batch
        total_results_per_task.extend(result)
        task+=1
        print(task)
        #await asyncio.sleep(1)
         # Pausar 1 segundo entre lotes para respetar el rate limit

    return total_results_per_task
def save_to_json(data, filename="commits_results_ssrf.json"):
    try:
        with open(filename, 'w') as file:
            json.dump(data, file,separators=(',', ':'))
        print(f"Datos guardados exitosamente en {filename}")
    except Exception as e:
        print(f"Error al guardar en archivo JSON: {e}")
# Función principal

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
        save_to_json(all_commits_executed)
        #print(all_commits_executed)
        # Procesar las respuestas
        
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
    start_time = time.time()  # Registrar el tiempo de inicio
    asyncio.run(main_())  # Ejecutar la función principal
    end_time = time.time()  # Registrar el tiempo de fin
    total_time = end_time - start_time  # Calcular el tiempo total en segundos
    total_time_minutes = total_time / 60  # Convertir a minutos
    print(f"Tiempo total de ejecución: {total_time_minutes:.2f} minutos")