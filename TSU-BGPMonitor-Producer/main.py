import threading
import traceback
from datetime import datetime
import os
import urllib3
from getRoutingData import getRoutingData

from utils.log_util import LOG_NAME, get_logger
from utils.config_util import get_config,get_start_datetime
from utils.common_util import exception_happen, send_email,admin_email

urllib3.disable_warnings()


kafka_logger = get_logger(LOG_NAME.PRODUCER_LOG)
error_logger = get_logger(LOG_NAME.ERROR_LOG,'error')

MINI_BVIEW_INTERVAL_TIMESTAMP = 8 * 60 * 60


start = get_start_datetime()


def do_something(start_timestamp):
    try:
        getRoutingData(start_timestamp)
    except Exception as e:
        exception_happen(e)
        send_email(admin_email,f'''
------------------------------------------
Exception Name:{e}
Exception Args:{e.args}
Exception Traceback{traceback.format_exc()}
------------------------------------------
    ''','Exception happened')





if __name__ == '__main__':
    log = get_logger(LOG_NAME.RUNNING_LOG)

    current_directory = os.path.join(os.getcwd(),'TSU-BGPMonitor-Producer')
    data_dir = 'data'
    start_timestamp = datetime.strptime(start, '%Y-%m-%d %H:%M').timestamp()
    
    bview_path = os.path.join(current_directory, data_dir, 'bview')
    dump_bview_path = os.path.join(current_directory, data_dir, 'bview_dump')
    update_path = os.path.join(current_directory, data_dir, 'update')
    
    os.makedirs(update_path, exist_ok=True)
    os.makedirs(bview_path, exist_ok=True)
    os.makedirs(dump_bview_path, exist_ok=True)
    
    
    do_something(start_timestamp)