import os
import dspy

from dotenv import load_dotenv
from modules.logger import GlobalLogger

load_dotenv()

log = GlobalLogger.log

# Change the value of the USE_OPENAI environment variable (.env) to True to use the OpenAI API
public_llm = os.getenv('USE_OPENAI', 'False').lower() == 'true'

if use_openai:
    turbo = dspy.OpenAI(model=os.getenv('OPENAI_MODEL'), max_tokens=250, api_key=os.getenv('OPENAI_API_KEY'))
    log.info("Using OpenAI API")
else:
    turbo = dspy.OllamaLocal(model=os.getenv('OLLAMA_MODEL'))
    log.info("Using Ollama Local Model")

# other keys
NVD_API_KEY = os.getenv('NVD_API_KEY')