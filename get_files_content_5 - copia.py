import time
import aiohttp
import asyncio
import json
import aiofiles
from aiolimiter import AsyncLimiter
import chardet

# Limitar el número de tareas en paralelo
semaphore = asyncio.Semaphore(45)  # Limitar a 25 tareas concurrentes
github_rate_limiter =  AsyncLimiter(max_rate=20000, time_period=3600)
# Obtener el contenido del archivo de la API
async def get_file_content(session, file_url):
    while True:
        #print(file_url)
        try:
            async with semaphore : 
                async with github_rate_limiter :
                    async with session.get(file_url) as response:
                        print(response.status)
                        if response.status == 200:
                            try : 
                                file_data = await response.read()
                                result = chardet.detect(file_data)
                                encoding = result['encoding']
                                file_content = file_data.decode(encoding)
                                return file_content
                            except Exception as e:
                                print(f'Error en el tipo de formato {e}') 
                                file_content = await response.read()
                                return file_content.decode('utf-8', errors='ignore')
                        elif response.status == 429:
                            print(f"Rate limit reached: {response.status}. Retrying...")
                            await asyncio.sleep(60)
                        elif response.status == 404 :
                            print(f"Error No Existe: {response.status}. Retrying...")
                            return None
                        elif response.status == 403:
                            print(f"Rate limit reached: {response.status}. Retrying...")
                            await asyncio.sleep(60)  # Esperar 60 segundos si se alcanza el límite
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
            data.extend(new_data)

            # Guardar el archivo JSON con los datos actualizados
            async with aiofiles.open(filename, mode='w') as file:
                await file.write(json.dumps(data))

            print(f"Se logró procesar con éxito  {len(new_data)} commits ")
    
    except Exception as e:
        print(f"Error al procesar el archivo: {e}")
files_proceced = []
save_files_task = []
# Obtener y procesar todos los archivos de un commit de forma paralela
async def process_commit_files(session, commit, previous_sha, keyword, prefix):
    tasks = []
    commit_url = commit["commit_url_"]
    files = commit["files"]
    sha = commit['sha']

    # Crear tareas para obtener el contenido de los archivos en paralelo
    for file in files:
        source_code_url_patched = file["raw_url"]
        source_code_url_vuln = file["raw_url"].replace(sha, previous_sha)
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
                        "patch": file["patch"] if "patch" in file else None,
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
    files_proceced.append(new_data)
    #save_files_task.append(asyncio.create_task(append_to_json_async(new_data, 'content_files_test5.json')))

async def run_tasks_in_batches_files(session, tasks):
    aux = 0
    for batch in asyncio.as_completed(tasks, timeout=None):
        await batch
        aux+=1
        print(aux)

# Función principal que procesa todos los commits en paralelo

async def load_save_data(filename='files_1.json'):
    try:
            async with aiofiles.open(filename, mode='r') as file:
                contenido = await file.read()
                data = json.loads(contenido)
            return data 
    except Exception as e :
        print(f'Error : {e}')

async def main_():
    """
    data =await load_save_data('append_files_1_part1.json')
    original_files = 0
    for i in data : 
        original_files+=len(i['files'])
    print(f'Orginal : {original_files}')
    exec_data =await load_save_data('content_files_test.json')
    exev_files = 0
    for i in exec_data : 
        try :
            exev_files+=len(i['files'])
        except : 
            continue
    print(f'Exect : {exev_files}')  
    """  
    resumme = await load_save_data('content_files_test8.json')
    #len(resumme)
    resume_sha = [file["sha"] for file in resumme  if "sha" in file]
    print(f'Datos ya procesados : {len(resume_sha)}')  
    tasks = []
    async with aiohttp.ClientSession() as session:
        # Leer el archivo JSON de commits
        async with aiofiles.open('append_files_4_part2.json', 'r') as file:
            data = json.loads(await file.read())
            print(f"Procesando {len(data)} commits")
            print(f'Faltantes : {len(data)-len(resume_sha)}')
            await asyncio.sleep(20)
            # Procesar cada commit de manera paralela
            for commit in data:
                if commit['sha'] in resume_sha :
                    print(f"Se omitira el commit {commit['sha']}")
                    continue
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
        await append_to_json_async(files_proceced,'content_files_test8.json')
        #await asyncio.gather(*save_files_task)
        #await asyncio.gather(*tasks)

if __name__ == "__main__":
    start_time = time.time()
    asyncio.run(main_())
    end_time = time.time()
    total_time = end_time - start_time
    print(f"Tiempo total de ejecución: {total_time:.2f} segundos")
