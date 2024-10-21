import argparse
import asyncio
import time
import aiofiles
import json
async def load_save_data(filename='files_1.json'):
    try:
            async with aiofiles.open(filename, mode='r') as file:
                contenido = await file.read()
                data = json.loads(contenido)
            return data 
    except Exception as e :
        print(f'Error : {e}')

async def main(file_input) : 
     save_data = await load_save_data(file_input)
     nulls_empty = [i for i in save_data if  i["all_diffs"] == None or len(i["all_diffs"] )== 0 ]
     print(f'total null data {len(save_data)}')
     print(f'total null data {len(nulls_empty)}')
     print(f'total null data {100*len(nulls_empty)/len(save_data)} %')
     pass


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Procesar diffs de commits y guardarlos en un archivo JSON.")
    parser.add_argument('-i', '--input', type=str, required=True, help="Archivo de entrada JSON con los commits.")
   
    args = parser.parse_args()

    start_time = time.time()  # Registrar el tiempo de inicio
    asyncio.run(main(args.input))  # Ejecutar la función principal
    end_time = time.time()  # Registrar el tiempo de fin
    total_time = end_time - start_time  # Calcular el tiempo total
    print(f"Tiempo total de ejecución: {total_time:.2f} segundos")