import requests
import re
import json

# Expresiones regulares para identificar el inicio del diff y las líneas añadidas/eliminadas
diff_start_pattern = re.compile(r'^diff --git a/(.+) b/(.+)')
vulnerable_pattern = re.compile(r'^-')  # Líneas eliminadas (-)
non_vulnerable_pattern = re.compile(r'^\+')  # Líneas añadidas (+)
neutral_pattern = re.compile(r'^[^-+]')  # Líneas sin cambios (neutrales)

# Función para procesar un diff y extraer las partes vulnerables y no vulnerables
def process_diff(diff_text):
    data = []
    current_file = None
    vulnerable_code = []
    non_vulnerable_code = []

    for line in diff_text.splitlines():
        # Detectar la ruta del archivo en el diff
        diff_match = diff_start_pattern.match(line)
        if diff_match:
            # Si ya tenemos un archivo procesado, guardarlo
            if current_file:
                data.append({
                    'file_path': current_file,
                    'vulnerable_code': "\n".join(vulnerable_code),
                    'non_vulnerable_code': "\n".join(non_vulnerable_code)
                })
            # Resetear los valores para el nuevo archivo
            current_file = diff_match.group(2)
            vulnerable_code = []
            non_vulnerable_code = []
            continue

        # Procesar las líneas vulnerables y no vulnerables
        if vulnerable_pattern.match(line):
            # Añadir línea a vulnerable eliminando el prefijo '-'
            vulnerable_code.append(line[1:])
        elif non_vulnerable_pattern.match(line):
            # Añadir línea a no vulnerable eliminando el prefijo '+'
            non_vulnerable_code.append(line[1:])
        elif neutral_pattern.match(line):
            # Añadir línea neutral a ambos
            vulnerable_code.append(line)
            non_vulnerable_code.append(line)

    # Agregar el último archivo procesado
    if current_file:
        data.append({
            'file_path': current_file,
            'vulnerable_code': "\n".join(vulnerable_code),
            'non_vulnerable_code': "\n".join(non_vulnerable_code)
        })

    return data

# Función para obtener el contenido del diff desde la URL
def get_diff_from_url(url):
    response = requests.get(url)
    if response.status_code == 200:
        return response.text
    else:
        print(f"Error al obtener el diff desde la URL: {response.status_code}")
        return None

# Función para guardar los datos en un archivo JSON
def save_to_json(data, output_file):
    with open(output_file, 'w') as f:
        json.dump(data, f, indent=4)

# URL del diff (puedes cambiarla por cualquier URL de diff)
diff_url = "https://github.com/elba7r/r-frameworking/commit/d03bb6e21a82d783ab1ac96f79ab9e22536c601f.diff"

# Nombre del archivo JSON de salida
output_file = "vulnerabilities_output5.json"

# Obtener el diff desde la URL
diff_text = get_diff_from_url(diff_url)

if diff_text:
    # Procesar el diff
    diff_data = process_diff(diff_text)
    # Guardar el resultado en un archivo JSON
    save_to_json(diff_data, output_file)
    print(f"Datos guardados en {output_file}")
