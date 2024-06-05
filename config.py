from dotenv import load_dotenv
import os

load_dotenv()

SHODAN_API_KEY = os.getenv('SHODAN_API_KEY')
OLLAMA_HOST = os.getenv('OLLAMA_HOST')
LLM_MODEL = os.getenv('LLM_MODEL')