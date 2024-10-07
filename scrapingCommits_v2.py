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
]

prefixes = [
    "vulnerable", "fix", "attack", "correct", "malicious", 
    "insecure", "vulnerability", "prevent", "protect", "issue", 
    "update", "improve", "change", "check"
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
    
    folder_path = f"vulnerabilities/{keyword}/{prefix}"
    if not os.path.exists(folder_path):
        os.makedirs(folder_path)
    
    json_file_name = f"{folder_path}/{file_path.replace('/', '_')}.json"
    
    try:
        with open(json_file_name, "w") as json_file:
            json.dump(data, json_file, indent=4)
        print(f"Guardado exitosamente en {json_file_name}")
    except Exception as e:
        print(f"Error al guardar el archivo JSON: {e}")

# Función para buscar commits
async def search_commits(session, query, page=1, per_page=100,max_page=10):
    while page<= max_page :
        params = {'q': query, 'per_page': per_page, 'page': page}
        search_limit, search_reset, core_limit, core_reset = await check_rate_limit(session)
        if search_limit<= 0 :
            print('sc'*40)
            await sleep_until_reset(search_reset)
        async with session.get(api_url_commits, headers={"Authorization": f"Bearer {gh_apikey}"}, params=params) as response:
            if response.status == 200:
                data = await response.json()
                return data.get('items', [])
            else:
                print(f"Error en la búsqueda de commits: {response.status}")
                return []
        page += 1

# Procesar los resultados asíncronamente
async def process_commits(session, k, p):
    query = k + "+" + p
    print(query)
    print('-'*60)
    resultados = await search_commits(session, query)

    for commit in resultados:
        sha = commit['sha']
        commit_url = commit['html_url']
        repo_info = commit['repository']
        owner = repo_info['owner']['login']
        repo = repo_info['name']
        search_limit, search_reset, core_limit, core_reset = await check_rate_limit(session)
        if core_limit<=0 : 
            await sleep_until_reset(core_reset)
        files = await get_commit_files(session, owner, repo, sha)

        for file in files:
            file_path = file['filename']
            file_type = os.path.splitext(file_path)[-1]

            try:
                previous_sha = commit['parents'][0]['sha']
                search_limit, search_reset, core_limit_, core_reset_ = await check_rate_limit(session)
                if core_limit_<=0 : 
                    await sleep_until_reset(core_reset_)           
                vuln_code = await get_file_content(session, owner, repo, file_path, previous_sha)
                fixed_code = await get_file_content(session, owner, repo, file_path, sha)

                if vuln_code and fixed_code:
                    save_to_json(vuln_code, fixed_code, file_type, commit_url, file_path, k, p)
            except Exception as e:
                print(f"Error al procesar el archivo {file_path}: {e}")

async def main():
    async with aiohttp.ClientSession() as session:
        # Verificar el límite de búsqueda y de core
        
        print('*'*60)
        # Si no hay límite de búsqueda, esperar hasta el reinicio
        if search_limit == 0:
            print('='*60)
            await sleep_until_reset(search_reset)

        # Limitar el número de tareas de búsqueda dependiendo del límite
        search_tasks = []
        for k in keywords:
            for p in prefixes:
                print(k+" "+p)
                print('-'*60)
                search_limit, search_reset, core_limit, core_reset = await check_rate_limit(session)
                if search_limit<=0 : 
                    print('?'*60)
                    await sleep_until_reset(search_reset)
                    search_limit, search_reset, core_limit, core_reset = await check_rate_limit(session)
                search_tasks.append(process_commits(session, k, p))
                
                
                    
                    

        # Ejecutar tareas de búsqueda en paralelo
        await asyncio.gather(*search_tasks)

if __name__ == "__main__":
    asyncio.run(main())
