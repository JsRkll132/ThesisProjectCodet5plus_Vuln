import os
from dotenv import load_dotenv


gh_apikey = os.getenv('TOKEN_GITHUB')
print(gh_apikey)