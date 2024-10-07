import os
import time
import asyncio
import aiohttp
import base64
import json
from dotenv import load_dotenv

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
    "session hijacking", "smurf", "unauthorized", "flooding", "tampering", 
    "sanitize", "sanitise"
]

prefixes = [
    "vulnerable", "fix", "attack", "correct", "malicious", 
    "insecure", "vulnerability", "prevent", "protect", "issue", 
    "update", "improve", "change", "check"
]

# Función asincrónica para verificar la tasa de búsqueda
async def check_search_rate_limit(session):
    async with session.get("https://api.github.com/rate_limit", headers={
        "Authorization": f"Bearer {gh_apikey}",
        "X-GitHub-Api-Version": "2022-11-28"
    }) as response:
        rate_limit = await response.json()
        search_rate = rate_limit.get('resources', {}).get('search', {})
        remaining = search_rate.get('remaining', 0)
        reset_time = search_rate.get('reset', 0)
        return remaining, reset_time

# Función asincrónica para controlar la tasa
async def sleep_if_rate_limited(session):
    remaining, reset_time = await check_search_rate_limit(session)
    if remaining == 0:
        wait_time = max(0, reset_time - time.time()) + 1  # Esperar hasta el reset
        print(f"Límite alcanzado, esperando {wait_time / 60:.2f} minutos...")
        await asyncio.sleep(wait_time)

# Función asincrónica para obtener los archivos modificados de un commit
async def get_commit_files(session, owner, repo, sha):
    commit_url = f"https://api.github.com/repos/{owner}/{repo}/commits/{sha}"
    await sleep_if_rate_limited(session)
    async with session.get(commit_url, headers={"Authorization": f"Bearer {gh_apikey}"}) as response:
        print(response.status)
        if response.status == 200:
            commit_data = await response.json()
            return commit_data.get('files', [])
        else:
            print(f"Error al obtener los archivos del commit: {response.status}")
            return []

# Función asincrónica para obtener el contenido de un archivo
async def get_file_content(session, owner, repo, file_path, ref):
    file_url = f"https://api.github.com/repos/{owner}/{repo}/contents/{file_path}?ref={ref}"
    await sleep_if_rate_limited(session)
    async with session.get(file_url, headers={"Authorization": f"Bearer {gh_apikey}"}) as response:
        print(response.status)
        if response.status == 200:
            file_data = await response.json()
            file_content = base64.b64decode(file_data['content']).decode('utf-8')
            return file_content
        else:
            print(f"Error al obtener el archivo: {response.status}")
            return None

# Función para guardar el código en un archivo JSON
def save_to_json(vuln_code, fixed_code, file_type, commit_url, file_path, keyword, prefix):
    data = {
        "vuln_code": vuln_code,
        "fixed_code": fixed_code,
        "file_type": file_type,
        "commit_url": commit_url,
        "file_path": file_path
    }
    
    folder_path = f"vulnerabilities_async/{keyword}/{prefix}"
    if not os.path.exists(folder_path):
        os.makedirs(folder_path)
    
    json_file_name = f"{folder_path}/{file_path.replace('/', '_')}.json"
    
    try:
        with open(json_file_name, "w") as json_file:
            json.dump(data, json_file, indent=4)
        
        print(f"Guardado exitosamente en {json_file_name}")
    except Exception as e:
        print(f"Error al guardar el archivo JSON: {e}")

# Función asincrónica para buscar commits
async def search_commits(session, query, max_pages=3):
    page = 1
    per_page = 100  # Máximo de resultados por página
    total_results = []
    
    while page <= max_pages:
        await sleep_if_rate_limited(session)

        async with session.get(api_url_commits, headers={"Authorization": f"Bearer {gh_apikey}", "X-GitHub-Api-Version": "2022-11-28"},
                               params={'q': query, 'per_page': per_page, 'page': page}) as result:

            if result.status == 200:
                data = await result.json()
                items = data.get('items', [])
                if not items:
                    print(f"No hay más resultados en la página {page}. Terminando búsqueda.")
                    break
                
                total_results.extend(items)
                print(f"Página {page}: {len(items)} resultados obtenidos.")
            else:
                print(f"Error: {result.status}")
                break

        page += 1
    
    return total_results

# Función principal para procesar los resultados
async def process_results():
    consultas_realizadas = set()

    async with aiohttp.ClientSession() as session:
        for k in keywords:
            for p in prefixes:
                query = k + "+" + p
                if query in consultas_realizadas:
                    print(f"Consulta '{query}' ya realizada. Saltando.")
                    continue  # Saltar consultas duplicadas
                print(f"Realizando búsqueda para '{query}'...")

                resultados = await search_commits(session, query)

                consultas_realizadas.add(query)
                
                # Procesar los resultados
                tasks = []
                for commit in resultados:
                    sha = commit['sha']
                    commit_url = commit['html_url']
                    repo_info = commit['repository']
                    owner = repo_info['owner']['login']
                    repo = repo_info['name']

                    # Obtener la lista de archivos modificados en el commit
                    files = await get_commit_files(session, owner, repo, sha)

                    # Procesar cada archivo modificado en el commit
                    for file in files:
                        file_path = file['filename']
                        file_type = os.path.splitext(file_path)[-1]

                        tasks.append(
                            process_file(session, owner, repo, sha, commit_url, file_path, file_type, k, p)
                        )

                await asyncio.gather(*tasks)

# Función para procesar archivos
async def process_file(session, owner, repo, sha, commit_url, file_path, file_type, keyword, prefix):
    try:
        # Código vulnerable (antes del commit)
        previous_sha = sha
        vuln_code = await get_file_content(session, owner, repo, file_path, previous_sha)
        # Código corregido (después del commit)
        fixed_code = await get_file_content(session, owner, repo, file_path, sha)

        if vuln_code and fixed_code:
            save_to_json(vuln_code, fixed_code, file_type, commit_url, file_path, keyword, prefix)
        else:
            print(f"No se pudo obtener el código completo para {file_path}")
    except Exception as e:
        print(f"Error al procesar el archivo {file_path}: {e}")

# Ejecutar el procesamiento
if __name__ == "__main__":
    asyncio.run(process_results())
