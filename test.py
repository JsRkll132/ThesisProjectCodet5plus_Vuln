import json

with open('vulnerability_dataset_filtered.json', 'r') as f:
    try:
        data = json.load(f)
        for idx, item in enumerate(data):
            if not isinstance(item, dict):
                print(f"Fila {idx} tiene una estructura incorrecta.")
    except json.JSONDecodeError as e:
        print(f"Error de JSON: {e}")