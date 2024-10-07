import os
import time
import requests as r
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
    "session hijacking", "smurf","unauthorized" , "flooding", "tampering", 
    "sanitize", "sanitise"
]

prefixes = [
    "vulnerable", "fix", "attack","correct" , "malicious", 
    "insecure", "vulnerability", "prevent", "protect", "issue", 
    "update", "improve", "change", "check"
]

# Función para verificar la tasa de búsqueda
def check_search_rate_limit():
    result = r.get("https://api.github.com/rate_limit", headers={
        "Authorization": f"Bearer {gh_apikey}",
        "X-GitHub-Api-Version": "2022-11-28"
    })
    rate_limit = result.json().get('resources', {}).get('search', {})
    remaining = rate_limit.get('remaining', 0)
    reset_time = rate_limit.get('reset', 0)
    return remaining, reset_time

# Función para controlar la tasa
def sleep_if_rate_limited():
    remaining, reset_time = check_search_rate_limit()
    if remaining == 0:
        wait_time = max(0, reset_time - time.time()) + 1  # Esperar hasta el reset
        print(f"Límite alcanzado, esperando {wait_time / 60:.2f} minutos...")
        time.sleep(wait_time)

# Función para obtener los archivos modificados de un commit específico
def get_commit_files(owner, repo, sha):
    commit_url = f"https://api.github.com/repos/{owner}/{repo}/commits/{sha}"
    sleep_if_rate_limited()
    response = r.get(commit_url, headers={"Authorization": f"Bearer {gh_apikey}"})
    
    if response.status_code == 200:
        return response.json().get('files', [])
    else:
        print(f"Error al obtener los archivos del commit: {response.status_code}")
        return []

# Función para obtener el contenido de un archivo en un commit específico
def get_file_content(owner, repo, file_path, ref):
    file_url = f"https://api.github.com/repos/{owner}/{repo}/contents/{file_path}?ref={ref}"
    sleep_if_rate_limited()
    response = r.get(file_url, headers={"Authorization": f"Bearer {gh_apikey}"})
    
    if response.status_code == 200:
        file_data = response.json()
        file_content = base64.b64decode(file_data['content']).decode('utf-8')
        return file_content
    else:
        print(f"Error al obtener el archivo: {response.status_code}")
        return None

# Función para guardar el código vulnerable y corregido en un archivo JSON en la carpeta correspondiente
def save_to_json(vuln_code, fixed_code, file_type, commit_url, file_path, keyword, prefix):
    # Crear la estructura de datos
    data = {
        "vuln_code": vuln_code,
        "fixed_code": fixed_code,
        "file_type": file_type,
        "commit_url": commit_url,
        "file_path": file_path
    }
    
    # Crear las carpetas basadas en keywords y prefixes
    folder_path = f"vulnerabilities/{keyword}/{prefix}"
    if not os.path.exists(folder_path):
        os.makedirs(folder_path)
    
    # Nombre del archivo JSON basado en la ruta del archivo
    json_file_name = f"{folder_path}/{file_path.replace('/', '_')}.json"
    
    try:
        # Guardar los datos en un archivo JSON
        with open(json_file_name, "w") as json_file:
            json.dump(data, json_file, indent=4)
        
        print(f"Guardado exitosamente en {json_file_name}")
    except Exception as e:
        print(f"Error al guardar el archivo JSON: {e}")

# Implementación de paginación para buscar commits
def search_commits(query, max_pages=10):
    page = 1
    per_page = 100  # Máximo de resultados por página
    total_results = []
    
    while page <= max_pages:
        # Chequeo de límite antes de cada solicitud
        sleep_if_rate_limited()

        # Realizar la solicitud con paginación
        result = r.get(
            url=api_url_commits,
            headers={"Authorization": f'Bearer {gh_apikey}', "X-GitHub-Api-Version": "2022-11-28"},
            params={'q': query, 'per_page': per_page, 'page': page}
        )

        if result.status_code == 200:
            data = result.json()
            items = data.get('items', [])
            if not items:
                print(f"No hay más resultados en la página {page}. Terminando búsqueda.")
                break
            
            total_results.extend(items)  # Guardar los resultados
            print(f"Página {page}: {len(items)} resultados obtenidos.")
        else:
            print(f"Error: {result.status_code}")
            break  # Rompe el ciclo si ocurre un error

        # Cerrar la conexión y avanzar a la siguiente página
        result.close()
        page += 1
    
    return total_results

# Procesar los resultados
consultas_realizadas = set()

for k in keywords:
    for p in prefixes:
        query = k + "+" + p
        if query in consultas_realizadas:
            print(f"Consulta '{query}' ya realizada. Saltando.")
            continue  # Saltar consultas duplicadas
        print(f"Realizando búsqueda para '{query}'...")

        resultados = search_commits(query)

        # Almacenar la consulta para evitar duplicados
        consultas_realizadas.add(query)
        
        # Procesar los resultados
        for commit in resultados:
            sha = commit['sha']
            commit_url = commit['html_url']
            repo_info = commit['repository']
            owner = repo_info['owner']['login']
            repo = repo_info['name']

            # Obtener la lista de archivos modificados en el commit
            files = get_commit_files(owner, repo, sha)

            # Procesar cada archivo modificado en el commit
            for file in files:
                file_path = file['filename']
                file_type = os.path.splitext(file_path)[-1]

                # Obtener el código antes y después del commit
                try:
                    # Código vulnerable (antes del commit)
                    previous_sha = commit['parents'][0]['sha']
                    vuln_code = get_file_content(owner, repo, file_path, previous_sha)
                    # Código corregido (después del commit)
                    fixed_code = get_file_content(owner, repo, file_path, sha)

                    # Guardar la información en un archivo JSON
                    if vuln_code and fixed_code:
                        save_to_json(vuln_code, fixed_code, file_type, commit_url, file_path, k, p)
                    else:
                        print(f"No se pudo obtener el código completo para {file_path}")
                except Exception as e:
                    print(f"Error al procesar el archivo {file_path}: {e}")
