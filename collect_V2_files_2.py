import os
import asyncio
import aiohttp
import base64
import json
from aiolimiter import AsyncLimiter
from dotenv import load_dotenv
import time
from itertools import cycle
import aiofiles
lock = asyncio.Lock()
# Cargar las variables de entorno
load_dotenv()

api_url_commits = "https://api.github.com/search/commits"
gh_apikey = os.getenv('TOKEN_GITHUB_2')
github_tokens = [
    os.getenv('TOKEN_GITHUB'),
    os.getenv('TOKEN_GITHUB_2'),
    os.getenv('TOKEN_GITHUB_3'),
    os.getenv('TOKEN_GITHUB_4'),
    os.getenv('TOKEN_GITHUB_5'),
    os.getenv('TOKEN_GITHUB_6'),
    os.getenv('TOKEN_GITHUB_7'),
    os.getenv('TOKEN_GITHUB_8'),
    os.getenv('TOKEN_GITHUB_9'),
    os.getenv('TOKEN_GITHUB_10'),
    os.getenv('TOKEN_GITHUB_11'),
    os.getenv('TOKEN_GITHUB_12'),
    os.getenv('TOKEN_GITHUB_13'),
    os.getenv('TOKEN_GITHUB_14'),
    os.getenv('TOKEN_GITHUB_15'),
    os.getenv('TOKEN_GITHUB_16'),
    os.getenv('TOKEN_GITHUB_17'),
    os.getenv('TOKEN_GITHUB_18'),
    os.getenv('TOKEN_GITHUB_19'),
    os.getenv('TOKEN_GITHUB_20'),
    os.getenv('TOKEN_GITHUB_21'),
    os.getenv('TOKEN_GITHUB_22'),
    os.getenv('TOKEN_GITHUB_23'),
    os.getenv('TOKEN_GITHUB_24'),
    os.getenv('TOKEN_GITHUB_25'),
    os.getenv('TOKEN_GITHUB_26'),
    os.getenv('TOKEN_GITHUB_27'),
    os.getenv('TOKEN_GITHUB_28'),
    os.getenv('TOKEN_GITHUB_29'),
    os.getenv('TOKEN_GITHUB_30'),
    os.getenv('TOKEN_GITHUB_31'),
    os.getenv('will'),
   
]
# Palabras clave y prefijos para las consultas
keywords =  [
    "sql injection", "unauthorised", "directory traversal", "rce", 
    "buffer overflow", "denial of service", "dos", "XXE", "vuln", "CVE", 
    "XSS", "NVD", "malicious", "cross site", "exploit", "remote code execution", 
    "XSRF", "cross site request forgery", "click jack", "clickjack", 
    "session fixation", "cross origin", "infinite loop", "brute force", 
    "cache overflow", "command injection", "cross frame scripting", "csv injection", 
    "eval injection", "execution after redirect", "format string", 
    "path disclosure", "function injection", "replay attack", 
    "session hijacking", "smurf", "unauthorized", "flooding", "tampering", 
    "sanitize", "sanitise"
]

prefixes = [
    "vulnerable", "fix", "attack","correct" , "malicious", 
    "insecure", "vulnerability", "prevent", "protect", "issue", 
    "update", "improve", "change", "check"
]
# Función para verificar la tasa de búsqueda y otras restricciones
async def check_rate_limit(session):
    global current_token
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
github_rate_limiter =  AsyncLimiter(max_rate=5000, time_period=3600) # Máximo 30 solicitudes por minuto
# Función para obtener el siguiente token
token_cycle = cycle(github_tokens)
def get_next_token():
    return next(token_cycle)
# Crear un semáforo para limitar el número de tareas que se ejescutan simultáneamente
semaphore = asyncio.Semaphore(10)  # Limitar a 10 tareas en paralelo

# Función para esperar hasta que el rate limit se reinicie y reintentar
async def execute_search_commit_request(session, params):
    while True:
        try : 
            async with semaphore:  # Controla el número de tareas en paralelo
                async with github_rate_limiter:  # Controla el número de solicitudes por minuto
                    async with session.get(api_url_commits, headers={"Authorization": f"Bearer {gh_apikey}"}, params=params,timeout=aiohttp.ClientTimeout(total=60)) as response:
                        if response.status == 200:
                            print("200 OK")
                            data = await response.json()
                            return data.get('items', [])
                        elif response.status == 403:
                            error_data = await response.json()
                            if "secondary rate limit" in error_data.get('message', '').lower():
                                print("Límite secundario alcanzado. Esperando 1 minutos...")
                                await asyncio.sleep(0.5)  # Espera de 5 minutos antes de reintentar
                            else:
                                print("Límite de búsqueda alcanzado. Esperando...")
                                search_limit, search_reset, _, _ = await check_rate_limit(session)
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
    
    for batch in asyncio.as_completed(tasks, timeout=None):
        result = await batch
        total_results_per_task.extend(result)
        await asyncio.sleep(1)
         # Pausar 1 segundo entre lotes para respetar el rate limit

    return total_results_per_task

async def search_files(session, query, page=1, per_page=100, max_page=10):
    tasks = []
    while page <= max_page:
        params = {'q': query, 'per_page': per_page, 'page': page}
        print(params)
        
        # Crear tarea y agregarla a la lista (pero no la ejecutamos aún)
        task = asyncio.create_task(execute_search_commit_request(session, params))
        tasks.append(task)
        page += 1
    return tasks
current_token = get_next_token()
# Obtener los archivos modificados de un commit específico
async def append_to_json(new_data, filename='files_1.json'):
    try:
        # Leer el archivo JSON actual
        async with lock:  # Asegurar que solo una tarea accede al archivo a la vez
            # Leer el archivo JSON de forma asíncrona
            async with aiofiles.open(filename, mode='r') as file:
                contenido = await file.read()
                data = json.loads(contenido)

            # Hacer append al arreglo
            data.append(new_data)

            # Guardar el archivo JSON de forma asíncrona
            async with aiofiles.open(filename, mode='w') as file:
                await file.write(json.dumps(data))
            print(f"Se logro procesar con exito : {new_data['sha']}")
    except Exception as e:
        print(f"Error al procesar el archivo: {e}")


async def get_commit_files(session, owner, repo, sha,commit_url,previous_sha,keyword,prefix):
    global current_token
    commit_url = f"https://api.github.com/repos/{owner}/{repo}/commits/{sha}"
    while True:
        try : 
            async with semaphore :
                async with github_rate_limiter :
                    async with session.get(commit_url, headers={"Authorization": f"Bearer {gh_apikey}"}) as response:
                        if response.status == 200:
                            commit_data = await response.json()
                            files  = commit_data.get('files', [])
                            files_ = [file for file in files if file['filename'].split('.')[-1] in ["py", "java", "js", "jsx", "rb", "php", "go", "c", "h", "cpp", "hpp", "ts", "tsx","cs"]]
                            if len(files_) == 0 : 
                                return                             
                            try : 
                                print(f'se pudo acceder al fichero :{sha}')
                                new_data = {
                                'keyword':keyword,
                                'prefix':prefix,
                                'files': files_,
                                'sha' : sha,
                                'previous_sha' : previous_sha,
                                'commit_url_': commit_url
                                }
                                asyncio.create_task(append_to_json(new_data,'files_2_.json'))
                                return "OK"
                            except : 
                                new_data = {
                                'keyword':keyword,
                                'prefix':prefix,
                                'files': files_,
                                'sha' : sha,
                                'previous_sha' : "",
                                'commit_url_': commit_url
                                }
                                asyncio.create_task(append_to_json(new_data,'files_2_.json'))
                                return "OK"
                        elif response.status == 403:
                            #current_token = get_next_token()
                            error_data = await response.json()
                            if "secondary rate limit" in error_data.get('message', '').lower():
                                print("Límite secundario alcanzado. Esperando unos segundos...")
                                await asyncio.sleep(0.5)  # Espera de 5 minutos antes de reintentar
                            else:
                                print("Límite de búsqueda alcanzado. Esperando...")
                                print("Se cambiara de token")
                                _, _, core_limit, core_reset = await check_rate_limit(session)
                                if core_limit == 0 : 
                                    await sleep_until_reset(core_reset)
                        else:
                            print(f"Error {response.status} en la búsqueda de archivos.")
                            return None
        except Exception as e : 
            print(f"Error de conexión: {e}") 
            await asyncio.sleep(5)
        
def save_to_json(data, filename="_commits_results_part2.json"):
    try:
        with open(filename, 'w') as file:
            json.dump(data, file, indent=4)
        print(f"Datos guardados exitosamente en {filename}")
    except Exception as e:
        print(f"Error al guardar en archivo JSON: {e}")
# Función principal
async def run_tasks_in_batches_files(session, tasks):
    total_results_per_task = []
    aux = 0
    for batch in asyncio.as_completed(tasks, timeout=None):
        result = await batch
        total_results_per_task.append(result)
        aux+=1
        print(aux)
        #await asyncio.sleep(1)
         # Pausar 1 segundo entre lotes para respetar el rate limit

    return total_results_per_task

async def load_save_data(filename='files_1.json'):
    try:
            async with aiofiles.open(filename, mode='r') as file:
                contenido = await file.read()
                data = json.loads(contenido)
            return data 
    except Exception as e :
        print(f'Error : {e}')

def save_to_json(data, filename="commits_results.json"):
    try:
        with open(filename, 'w') as file:
            json.dump(data, file)
        print(f"Datos guardados exitosamente en {filename}")
    except Exception as e:
        print(f"Error al guardar en archivo JSON: {e}")

async def main_():
    #data_ = await load_save_data('files_2.json')
    data_ = await load_save_data('empty_files_2.json')
    
    load_data = [file['sha'] for file in data_  ]
    #load_data = [file for file in data_ if len(file['files']) == 0   ]
    #print(f"Archivos supuestamente vascios {len(load_data)}")
    #save_to_json(load_data,"empty_files_2.json")
    #return
    print(f'{len(load_data)} datos cargados...')
    tasks = []
    async with aiohttp.ClientSession() as session:
        with open('_commits_results_part2.json','r+') as file : 
            data = json.load(file)
            print(len(data))
            
            for commit in data:
                try :
                    sha = commit['sha']
                    commit_url = commit['html_url']
                    repo_info = commit['repository']
                    owner = repo_info['owner']['login']
                    repo = repo_info['name']
                    previous_sha = commit['parents'][0]['sha']
                    keyword = commit['keyword']
                    prefix = commit['prefix']
                    if sha in load_data :
                        print(f'Creando tarea para : {commit_url}')
                        tasks.append(asyncio.create_task(get_commit_files(session,owner, repo, sha,commit_url,previous_sha,keyword,prefix)))
                        #print(f"Commit {commit_url} ya existe en load_data. Saltando...")
                        #continue  
                    
                except Exception as e :
                    print(f'Ocurrio un error : {e}')
            all_data_files =await  run_tasks_in_batches_files(session=session,tasks=tasks) 
            #save_to_json(all_data_files,"location_commit_files.json")
    #    print(data[0])
    
        
    

if __name__ == "__main__":
    start_time = time.time()  # Registrar el tiempo de inicio
    asyncio.run(main_())  # Ejecutar la función principal
    end_time = time.time()  # Registrar el tiempo de fin
    total_time = end_time - start_time  # Calcular el tiempo total
    print(f'start time : {start_time}, end time : {end_time}')
    print(f"Tiempo total de ejecución: {total_time:.2f} segundos")