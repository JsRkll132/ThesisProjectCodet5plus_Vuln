import base64
import time
import aiohttp
import asyncio
import json
import aiofiles
import os

from aiolimiter import AsyncLimiter
# Limitar el número de tareas en paralelo
semaphore = asyncio.Semaphore(10)  # Limitar a 25 tareas concurrentes
gh_apikey = os.getenv('TOKEN_GITHUB')
github_rate_limiter =  AsyncLimiter(max_rate=5000, time_period=3600)
# Obtener el contenido del archivo de la API

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

async def get_file_content(session, file_url):
    while True:
        #print(file_url)
        try:
            async with semaphore :
                async with github_rate_limiter :
                    async with session.get(file_url, headers={"Authorization": f"Bearer {gh_apikey}"}) as response:
                        print(response.status)
                        if response.status == 200:
                            file_data =  await response.json()
                            file_content = base64.b64decode(file_data['content']).decode('utf-8')
                            return file_content
                        elif response.status == 429:
                            print(f"Rate limit reached: {response.status}. Retrying...")
                            await asyncio.sleep(5)
                        elif response.status == 404 :
                            print(f"Error No Existe: {response.status}. Retrying...")
                            return None
                        elif response.status == 403:
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
                          
        except Exception as e:
            print(f"Error al obtener el archivo {file_url}: {e}")
            await asyncio.sleep(5)
lock = asyncio.Lock()
# Hacer append a un archivo JSON de forma asíncrona
# Función para agregar datos a un archivo JSON de forma asíncrona
async def append_to_json_async(new_data, filename='files_1.json'):
    try:
        async with lock:  # Asegurar que solo una tarea acceda al archivo a la vez
            # Leer el archivo JSON de forma asíncrona
            async with aiofiles.open(filename, mode='r') as file:
                contenido = await file.read()
                try:
                    data = json.loads(contenido)
                except json.JSONDecodeError:
                    data = []

            # Agregar los nuevos datos
            data.append(new_data)

            # Guardar el archivo JSON con los datos actualizados
            async with aiofiles.open(filename, mode='w') as file:
                await file.write(json.dumps(data))

            print(f"Se logró procesar con éxito el commit: {new_data['sha']}")
    
    except Exception as e:
        print(f"Error al procesar el archivo: {e}")

# Obtener y procesar todos los archivos de un commit de forma paralela
async def process_commit_files(session, commit, previous_sha, keyword, prefix):
    tasks = []
    commit_url = commit["commit_url_"]
    files = commit["files"]
    sha = commit['sha']

    # Crear tareas para obtener el contenido de los archivos en paralelo
    for file in files:
        source_code_url_patched = file["contents_url"]
        source_code_url_vuln = file["contents_url"].replace(sha, previous_sha)
        filename = file['filename']
        filetype = filename.split('.')[-1]

        # Crear tareas para obtener el contenido parcheado y vulnerable
        tasks.append(asyncio.create_task(get_file_content(session, source_code_url_patched)))
        tasks.append(asyncio.create_task(get_file_content(session, source_code_url_vuln)))

    # Ejecutar todas las tareas de forma paralela
    results = await asyncio.gather(*tasks)
    new_data = {}
    # Organizar los datos para el archivo JSON
    try : 
        new_data = {
                "keyword": keyword,
                "prefix": prefix,
                "files": [
                    {
                        "sha": file["sha"],
                        "filename": file["filename"],
                        "status": file["status"],
                        "additions": file["additions"],
                        "deletions": file["deletions"],
                        "changes": file["changes"],
                        "blob_url": file["blob_url"],
                        "raw_url": file["raw_url"],
                        "filetype": filetype,
                        "source_code_url_patched": source_code_url_patched,
                        "source_code_url_vuln": source_code_url_vuln,
                        "patch": file["patch"],
                        "content_patched": results[i * 2],  # Contenido parcheado
                        "content_vuln": results[i * 2 + 1]  # Contenido vulnerable
                    }
                    for i, file in enumerate(files)
                ],
                "sha": sha,
                "previous_sha": previous_sha,
                "commit_url_": commit_url
            }
    
    except Exception as e :
        print(f'Error: {e}')
    

    # Guardar el nuevo commit y sus archivos en el archivo JSON
    asyncio.create_task(append_to_json_async(new_data, 'content_files_test.json'))
async def run_tasks_in_batches_files(session, tasks):
    total_results_per_task = []
    aux = 0
    for batch in asyncio.as_completed(tasks, timeout=None):
        result = await batch
        total_results_per_task.append(result)
        aux+=1
        print(aux)
# Función principal que procesa todos los commits en paralelo
async def main_():
    tasks = []
    async with aiohttp.ClientSession() as session:
        # Leer el archivo JSON de commits
        async with aiofiles.open('append_files_1_part1.json', 'r') as file:
            data = json.loads(await file.read())
            print(f"Procesando {len(data)} commits")

            # Procesar cada commit de manera paralela
            for commit in data:
                try:
                    sha = commit['sha']
                    previous_sha = commit['previous_sha']
                    keyword = commit['keyword']
                    prefix = commit['prefix']

                    tasks.append(asyncio.create_task(
                        process_commit_files(session, commit, previous_sha, keyword, prefix)
                    ))
                except Exception as e:
                    print(f"Ocurrió un error procesando el commit: {e}")
            await  run_tasks_in_batches_files(session=session,tasks=tasks) 
        # Ejecutar todas las tareas en paralelo para procesar los commits
        #await asyncio.gather(*tasks)

if __name__ == "__main__":
    start_time = time.time()
    asyncio.run(main_())
    end_time = time.time()
    total_time = end_time - start_time
    print(f"Tiempo total de ejecución: {total_time:.2f} segundos")
