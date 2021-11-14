from pydantic import BaseSettings
from decouple import config

class AuthSettings(BaseSettings):
    JWT_SECRET_KEY: str = config('SECRET_KEY')
    ES256_KEY: str = config("ES256_KEY")
    JWT_ALGO: str = config("JWT_ALGO")
    ES256_KID: str = config("ES256_KID")

class Settings( AuthSettings):
    pass

settings = Settings()
