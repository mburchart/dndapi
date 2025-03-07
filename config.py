import os

class Config:
    _instance = None  # Singleton-Instanz

    def __new__(cls):
        """ Singleton-Mechanismus: Erstellt die Instanz nur einmal """
        if cls._instance is None:
            cls._instance = super(Config, cls).__new__(cls)
            cls._instance._initialized = False
        return cls._instance
    
    def __init__(self):
        if self._initialized:
            return
        self._initialized = True
        self.postgres = {
            "host": os.getenv("DB_HOST", "localhost"),
            "port": os.getenv("DB_PORT", "5432"),
            "user": os.getenv("DB_USER", "postgres"),
            "password": os.getenv("DB_PASSWORD", "password"),
            "database": os.getenv("DB_NAME", "mydatabase")
        }
        self.logger = {
            "name": os.getenv("LOG_NAME", "AppLogger"),
            "file": os.getenv("LOG_FILE", "app.log"),
            "level": os.getenv("LOG_LEVEL", "DEBUG"),
            "path": os.getenv("LOG_PATH", "logs")
        }
    
    @staticmethod
    def get_instance():
        if Config._instance is None:
            Config._instance = Config()
        return Config._instance


