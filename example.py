import concurrent.futures
import requests

# Función para realizar una solicitud HTTP
def fetch_url(url):
    response = requests.get(url)
    return response.url

urls = ['https://example.com', 'https://example.org', 'https://example.net','https://example.com', 'https://example.org', 'https://example.net','https://example.com', 'https://example.org', 'https://example.net','https://example.com', 'https://example.org', 'https://example.net','https://example.com', 'https://example.org', 'https://example.net','https://example.com', 'https://example.org', 'https://example.net']

# Usamos ThreadPoolExecutor con 5 hilos
with concurrent.futures.ThreadPoolExecutor(max_workers=1) as executor:
    # Ejecutamos fetch_url para cada URL en paralelo
    results = executor.map(fetch_url, urls)

for result in results:
    print(result)