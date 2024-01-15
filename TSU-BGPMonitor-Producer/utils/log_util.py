from enum import Enum
import logging
from logging.handlers import RotatingFileHandler
from utils.config_util import get_config
import os


LOG_LEVEL = get_config('log_level')
BACKUP_COUNT = 5
LOGGING_FORMAT = logging.Formatter('%(asctime)s - %(levelname)s - %(filename)s - %(funcName)s - %(lineno)s - %(message)s')
LOGS_DIR = 'logs'


class LOG_NAME(Enum):

    PRODUCER_LOG = 'kafka_producer'
    ERROR_LOG = 'error'
    ERROR_LOG_FILE_NAME = 'error.log'
    RUNNING_LOG = 'running'



log_level_mapping = {
    'info':logging.INFO,
    'debug':logging.DEBUG,
    'warn':logging.WARN,
    'error':logging.ERROR,
}

logging.getLogger("requests").setLevel(logging.WARNING)
logging.getLogger("urllib3").setLevel(logging.WARNING)
logging.basicConfig(level=log_level_mapping[LOG_LEVEL])

logger_cache = {}

def _init_loggper(logger_name,level):
    current_directory = os.getcwd()
    os.makedirs(os.path.join(current_directory,'TSU-BGPMonitor-Producer', LOGS_DIR, logger_name), exist_ok=True)
    handler = RotatingFileHandler(os.path.join(current_directory,'TSU-BGPMonitor-Producer', LOGS_DIR, logger_name,f'{logger_name}.log'), encoding='UTF-8',maxBytes=5*1024*1024,backupCount=BACKUP_COUNT)
    handler.setLevel(log_level_mapping[level])
    handler.setFormatter(LOGGING_FORMAT)
    logger = logging.getLogger(logger_name)
    logger.addHandler(handler)
    logger_cache[logger_name] = logger

def get_logger(logger_name,level='debug'):
    
    if logger_name not in logger_cache:
        _init_loggper(logger_name.value,level)

    return logger_cache[logger_name.value]