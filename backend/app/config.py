from pathlib import Path
from pydantic_settings import BaseSettings

BASE_DIR = Path(__file__).resolve().parent.parent


class Settings(BaseSettings):
    APP_NAME: str = "DarkIntel"
    DATABASE_URL: str = f"sqlite:///{BASE_DIR / 'darkintel.db'}"

    JWT_SECRET: str = "CHANGE_ME"
    JWT_ALGORITHM: str = "HS256"
    JWT_EXPIRE_MINUTES: int = 1440

    SEED_ADMIN_EMAIL: str = "admin@darkintel.local"
    SEED_ADMIN_PASSWORD: str = "Password@123"

    class Config:
        env_file = ".env"


settings = Settings()