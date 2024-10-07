import json
import math

# Leer el archivo JSON que contiene un arreglo
def read_json_file(filename):
    try:
        with open(filename, 'r') as file:
            data = json.load(file)
            return data
    except Exception as e:
        print(f"Error al leer el archivo: {e}")
        return None

# Dividir el arreglo en partes iguales
def divide_into_batches(data, num_batches):
    batch_size = math.ceil(len(data) / num_batches)
    return [data[i:i + batch_size] for i in range(0, len(data), batch_size)]

# Guardar cada lote en un archivo separado
def save_batches_to_files(batches, base_filename):
    for i, batch in enumerate(batches):
        filename = f"{base_filename}_part{i+1}.json"
        try:
            with open(filename, 'w') as file:
                json.dump(batch, file)
            print(f"Datos guardados exitosamente en {filename}")
        except Exception as e:
            print(f"Error al guardar en el archivo {filename}: {e}")

# Función principal para dividir y guardar
def main():
    original_filename = 'AppendData_repoFilesDirectories\\append_files_4.json'  # El archivo JSON original
    base_output_filename = 'append_files_4'  # Prefijo para los archivos de salida
    num_batches = 2  # Número de archivos a crear

    # Leer el archivo JSON original
    data = read_json_file(original_filename)

    if data:
        # Dividir el arreglo en 4 lotes
        batches = divide_into_batches(data, num_batches)
        
        # Guardar cada lote en un archivo separado
        save_batches_to_files(batches, base_output_filename)

if __name__ == "__main__":
    main()
