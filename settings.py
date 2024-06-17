import os
import dspy

from dotenv import load_dotenv
from modules.logger import GlobalLogger

load_dotenv()

# Instantiate the logger
log = GlobalLogger.log

# API and Model Keys
NVD_API_KEY = os.getenv('NVD_API_KEY')
SHODAN_API_KEY = os.getenv('SHODAN_API_KEY')
OPENAI_MODEL = os.getenv('OPENAI_MODEL')
OPENAI_KEY = os.getenv('OPENAI_API_KEY')
OLLAMA_MODEL = os.getenv('OLLAMA_MODEL')
OLLAMA_HOST = os.getenv('OLLAMA_HOST')
PUBLIC_LLM = os.getenv('PUBLIC_LLM', 'False').lower() == 'true'

# Change the value of the USE_OPENAI environment variable (.env) to True to use the OpenAI API
public_llm = os.getenv('PUBLIC_LLM', 'False').lower() == 'true'

if PUBLIC_LLM:
    turbo = dspy.OpenAI(model=os.getenv('OPENAI_MODEL'), max_tokens=250, api_key=os.getenv('OPENAI_API_KEY'))
    log.info("Using OpenAI API")
else:
    turbo = dspy.OllamaLocal(model=os.getenv('OLLAMA_MODEL'))
    log.info("Using Ollama Local Model")
