import logging
import os
from datetime import datetime
from config import Config

class Logger:
    
    _instance = None

    def __new__(cls):
        
        if cls._instance is None:
            cls._instance = super(Logger, cls).__new__(cls)
            cls._instance._initialized = False
        
        return cls._instance
    
    def __init__(self):
        
        if self._initialized:
            return
        
        self._initialized = True     

        os.makedirs(Config.get_instance().logger["path"], exist_ok=True)
        log_path = os.path.join("logs", Config.get_instance().logger["file"])

        self.logger = logging.getLogger(Config.get_instance().logger["name"])
        level = getattr(logging, Config.get_instance().logger["level"].upper(), logging.INFO)
        self.logger.setLevel(level)

        formatter = logging.Formatter("[%(asctime)s] %(levelname)s - %(message)s", "%Y-%m-%d %H:%M:%S")

        console_handler = logging.StreamHandler()
        console_handler.setFormatter(formatter)

        file_handler = logging.FileHandler(log_path, encoding="utf-8")
        file_handler.setFormatter(formatter)

        self.logger.addHandler(console_handler)
        self.logger.addHandler(file_handler)

    def info(self, message: str):
        self.logger.info(message)

    def warn(self, message: str):
        self.logger.warning(message)

    def error(self, message: str):
        self.logger.error(message)

    def exception(self, message: str):
        self.logger.exception(message)

    @staticmethod
    def get_instance():
        if Logger._instance is None:
            Logger._instance = Logger()
        return Logger._instance
