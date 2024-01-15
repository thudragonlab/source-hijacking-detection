from datetime import datetime
import ipaddress
from multiprocessing import Pool, Manager
import atexit
import time
from confluent_kafka.admin import AdminClient, NewTopic
from Producer import KafkaProducer
from utils.log_util import LOG_NAME, get_logger
from utils.config_util import get_config
from utils.common_util import bgpdump_file, bgpdump_file_popen,download, get_latest_bview_online
import hashlib
import math
import os

kafka_config = get_config('kafka_config')
use_local_files = get_config('use_local_files')
kafka_hosts = kafka_config["addresses"]
kafka_topic = kafka_config["topic"]
# partition_count = kafka_config["partition_count"]
logger = get_logger(LOG_NAME.PRODUCER_LOG)

THREAD_POOL_SIZE = 8
manager = Manager()
atexit.register(manager.shutdown)
# global_queue = manager.Queue()

result_queue = manager.Queue()

producer_opt_queue_list = []
producer_msg_queue_list = []

msg_queue_index_cache = {}

partition_mapping = {
    'c': 0,
    'a': 1,
    '9': 2,
    '0': 3,
    '1': 4,
    '3': 5,
    'e': 6,
    'f': 7,
    '5': 8,
    'd': 9,
    '2': 10,
    '8': 11,
    '6': 12,
    '7': 13,
    'b': 14,
    '4': 15,
}


def make_producer_id(id):
    return f'Producer{id}'


def ec(e):
    raise e


def to_loop(forever=True):
    if forever:
        return True


def make_date_in_file_name(datetime_obj):
    return datetime_obj.strftime('%Y.%m'), datetime_obj.strftime('%Y%m%d.%H%M')


def get_data_by_timestamp(_start_timestamp):
    _start_timestamp = _start_timestamp - (_start_timestamp % (5 * 60))
    current_date = datetime.fromtimestamp(_start_timestamp)
    if current_date.timestamp() < datetime.now().timestamp() - 5 * 60:
        date_str, time_str = make_date_in_file_name(
            datetime.fromtimestamp(_start_timestamp))
        url = f'https://data.ris.ripe.net/rrc00/{date_str}/updates.{time_str}.gz'
        return url
    else:
        return False


def get_bview_data_by_timestamp(_start_timestamp):
    if _start_timestamp % (8 * 60 * 60) == 0:
        current_date = datetime.fromtimestamp(_start_timestamp)
        if datetime.now().timestamp() - current_date.timestamp() >= 150 * 60:
            date_str, time_str = make_date_in_file_name(
                datetime.fromtimestamp(_start_timestamp))
            url = f'https://data.ris.ripe.net/rrc00/{date_str}/bview.{time_str}.gz'
            return url
        else:
            False
    else:
        return False



def do_producer2(kafka_config, logger, i, opt_queue,msg_queue,result_queue):
    KafkaProducer(kafka_config, logger, i, opt_queue,msg_queue,result_queue)
    




def add_producer_task(_path):
    with open(_path, 'r') as f:
        all_data = f.readlines()
        partition_size = math.ceil(len(all_data) / THREAD_POOL_SIZE)
        logger.info(partition_size)
        processing_producer_list = []
        for i in range(THREAD_POOL_SIZE):
            producer_id = make_producer_id(i)

            start = i * partition_size
            end = (i + 1) * partition_size
            producer_opt_queue_list[i].put(
                ('sendjsondata', all_data[start:end], start, 'bview'))
            processing_producer_list.append(producer_id)
        waiting_until_processes_finish(processing_producer_list)


def waiting_until_processes_finish(processing_producer_list):
    while True:
        try:
            data = result_queue.get_nowait()
            processing_producer_list.remove(data)
            if len(processing_producer_list) == 0:
                break
        except Exception as e:
            time.sleep(0.1)


def create_producers(pool):
    atexit.register(pool.terminate)
    for i in range(THREAD_POOL_SIZE):
        opt_queue = manager.Queue()
        msg_queue = manager.Queue()
        producer_opt_queue_list.append(opt_queue)
        producer_msg_queue_list.append(msg_queue)
        pool.apply_async(do_producer2, (kafka_config, logger, i, opt_queue,msg_queue,result_queue),
                         error_callback=ec)
    pool.close()

    
def getRoutingData(start_timestamp):
    origin_start_timestamp = start_timestamp
    client = AdminClient({'bootstrap.servers': kafka_hosts[0]})
    topics = client.list_topics()
    need_create_topics = []
    if kafka_topic not in topics.topics:
        new_topic = NewTopic(kafka_topic,
                             num_partitions=16,
                             replication_factor=1)
        need_create_topics.append(new_topic)
    if len(need_create_topics):
        client.create_topics(need_create_topics)


    pool = Pool(THREAD_POOL_SIZE)
    # New producer
    create_producers(pool)

    my_path = os.path.join(os.getcwd(), 'data', 'update')
    bview_path = os.path.join(os.getcwd(), 'data', 'bview')
    dump_bview_path = os.path.join(os.getcwd(), 'data', 'bview_dump')
    last_timestamp = None
    
    while to_loop():
        # # TODO get bview path if time is good
        logger.debug(f'start_timestamp => {start_timestamp}')
        need_bview = start_timestamp % (8 * 60 * 60) == 0 and start_timestamp == origin_start_timestamp

        # download bview and dump
        if need_bview:
            # get url
            bview_url = get_bview_data_by_timestamp(start_timestamp) or get_latest_bview_online(start_timestamp)
            bview_name = bview_url.rsplit('/')[-1]
            print(bview_url)
            
            # download
            gz_path = download(bview_url, os.path.join(bview_path, bview_name))
            
            # get bgpdump save path
            bview_txt_path = os.path.join(dump_bview_path, bview_name)
            
            # scan chache
            if not os.path.exists(bview_txt_path) or not use_local_files:
                bgpdump_file(gz_path, bview_txt_path)
            
            # send to kafka
            add_producer_task(bview_txt_path)

        
        # get Update file path
        path = get_data_by_timestamp(start_timestamp)

        if not path:
            
            while start_timestamp > datetime.now().timestamp() - 11 * 60:
                time.sleep(30)
                
            path = get_data_by_timestamp(start_timestamp)
        file_name = path.split('/')[-1]
        
        # download
        gz_path = download(path, os.path.join(my_path, file_name))

        read_update_stream = False
        for i in bgpdump_file_popen(gz_path):
            i = i.strip().decode('utf-8')
            if 'logging to syslog' in i:
                continue
            i_s = i.split('|')
            
            if i_s[2] not in ['A','W']:
                continue
            
            if len(i_s) < 5:
                logger.error(i_s)
                continue

            now_timestamp = i_s[1]
            prefix = i_s[5]
            
            if not read_update_stream:
                read_update_stream = True
            
            p = ipaddress.ip_network(prefix.strip()).exploded
            
            if ':' in prefix:
                pf = p.split(':')[0]
            else:
                pf = p.split('.')[0]
                
            if pf in msg_queue_index_cache:
                msg_queue_index = msg_queue_index_cache[pf]
            else:
                msg_queue_index = int(partition_mapping[hashlib.md5(pf.encode()).hexdigest()[0]]/2)
                msg_queue_index_cache[pf] = msg_queue_index
                
                
            if not last_timestamp:
                last_timestamp = now_timestamp
                
            if now_timestamp != last_timestamp:
                logger.debug(f'update!! {last_timestamp} => {now_timestamp}')
                last_timestamp = now_timestamp

            producer_msg_queue_list[msg_queue_index].put((i, 'update'))
            
        if read_update_stream:
            start_timestamp += 5 * 60

    pool.join()

    # 3
