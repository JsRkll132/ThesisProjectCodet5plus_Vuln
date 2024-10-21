import json

def convert_json_ident4_to_iden0(input_file, output_file):
    with open(input_file, 'r') as file:
        data = json.load(file)
    
    # Guarda el JSON en el archivo de salida sin indentación
    with open(output_file, 'w') as file:
        json.dump(data, file, separators=(',', ':'))  # Sin espacios ni indentación

# Ejemplo de uso
convert_json_ident4_to_iden0('_commits_results_part1.json', '_commits_results_part1_iden0.json')
