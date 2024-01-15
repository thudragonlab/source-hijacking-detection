from utils.log_util import  get_logger,LOG_NAME, make_log_queue
from utils.config_util import get_config
from datetime import datetime
import multiprocessing
from utils.legal_moas_util import init_legal_moas
from utils.mongo_util import collection_dict,gol_db
from utils.common_util import exception_happen, timestamp2date
from src.Consumer import pre_start_consumer


MINI_BVIEW_INTERVAL_TIMESTAMP = 8 * 60 * 60


start = get_config('forever_start_datetime')


def do_something():
    try:
        pre_start_consumer()
        
    except Exception as e:
        exception_happen(e)


def worker_process(queue):
    # 配置子进程的日志处理器
    logger = get_logger(LOG_NAME.RUNNING_LOG)

    # 从队列中获取日志消息并写入日志文件
    while True:
        record = queue.get()
        logger.handle(record)


if __name__ == '__main__':
    queue = multiprocessing.Queue()
    
    process = multiprocessing.Process(target=worker_process, args=(queue,))
    process.start()

    log = make_log_queue(queue)
    
    init_legal_moas()

    start_timestamp = datetime.strptime(start, '%Y-%m-%d %H:%M').timestamp()
    timestamp = start_timestamp
    for c_name in collection_dict:
        delete_result = gol_db[c_name].delete_many({
                    'start_timestamp': {
                        '$gte': timestamp
                    }
                })
        log.info(f'Delete {delete_result.deleted_count} data from {timestamp2date(timestamp)} in collection[{c_name}]')
    
    
    do_something()