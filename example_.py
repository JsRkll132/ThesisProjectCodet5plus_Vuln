import json
import requests as r
import asyncio 
import aiohttp

async def make_task (session,request) : 
    try : 
        
        async with session.get("https://raw.githubusercontent.com/lukebrogan-mend/Java-Demo/98609b6706c0a0de472f236f5b56f33aadffeb3b/src/main/java/org/t246osslab/easybuggy/core/servlets/AdminsMainServlet.java") as response : 
            print(request)
            return await response.text()
    except Exception as e : 
        print(f'error : {e}')
def save_to_json(data, filename="exmpl__.json"):
    try:
        with open(filename, 'w') as file:
            json.dump(data, file)
        print(f"Datos guardados exitosamente en {filename}")
    except Exception as e:
        print(f"Error al guardar en archivo JSON: {e}")
async def main() :
    tasks = [ ]
    async with aiohttp.ClientSession() as session : 
        for i in range(0,50) :
            print(i)
            tasks.append(asyncio.create_task(make_task(session,i)))
        data = await asyncio.gather(*tasks)
        data_ = [{'file':file} for file in data]
        save_to_json(data=data_)
if __name__ =='__main__' : 
    asyncio.run(main())