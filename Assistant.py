from decouple import config as env_config
from openai import OpenAI

API_KEY = env_config("OPENAI_KEY", cast=str, default="") # load the OPEN_KEY from .env file

# this assistant class takes a domain and api key as an argument and responds to prompts based on the specified domain
class Assistant:
    def __init__(self, domain: str, api_key: str = API_KEY):
        self.domain = domain
        self.client = OpenAI(
            api_key=api_key
        )



    def prompt(self, prompt_text: str) -> str:
        text = self.client.chat.completions.create(
            model="gpt-5-nano",
            messages=[
                {"role": "system", "content": f"You are a helpful expert to the user and your domain of knowledge is {self.domain}"},
                {"role": "user", "content": prompt_text}
            ])

        return text.choices[0].message.content

