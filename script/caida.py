from datetime import datetime
import time
import urllib3
import requests
import os

from utils.common_util import exception_happen,download_file
from utils.log_util import get_logger,LOG_NAME
from utils.mongo_util import get_daily_collection_name,init_transitory_daily_collection
from utils.config_util import get_config

urllib3.disable_warnings()

TMP_PATH = f'{os.getcwd()}/{get_config("tmp_name")}'

db_name = 'serial1'
log = get_logger(LOG_NAME.CAIDA_LOG)

def download_new_file():
    file_name = f"{datetime.now().strftime('%Y%m')}01.as-rel.txt.bz2"
    url = f'https://publicdata.caida.org/datasets/as-relationships/serial-1/{file_name}'
    dst = download_file(url, os.path.join(TMP_PATH, file_name))
    cmd = f'bzip2 -dc {dst} >  {dst}.txt'
    os.system(cmd)
    os.remove(dst)
    dst = f'{dst}.txt'
    return dst


def process_data(_txt_path):
    result = {}
    with open(_txt_path, 'r') as f:
        for line in f.readlines():
            if '#' in line:
                continue
            as1, as2, relation_code = line.strip().split('|')
            if as1 not in result:
                result[as1] = {
                    "customer-ases": [],
                    "provider-ases": [],
                    "peer-ases": [],
                    "customer-ases-count": 0,
                    "provider-ases-count": 0,
                    "peer-ases-count": 0,
                }
            if as2 not in result:
                result[as2] = {
                    "customer-ases": [],
                    "provider-ases": [],
                    "peer-ases": [],
                    "customer-ases-count": 0,
                    "provider-ases-count": 0,
                    "peer-ases-count": 0,
                }
            if relation_code == '0':
                result[as2]["peer-ases"].append(as1)
                result[as2]["peer-ases-count"] += 1
                result[as1]["peer-ases"].append(as2)
                result[as1]["peer-ases-count"] += 1
            if relation_code == '-1':
                result[as1]["customer-ases"].append(as2)
                result[as1]["customer-ases-count"] += 1
                result[as2]["provider-ases"].append(as1)
                result[as2]["provider-ases-count"] += 1
    return result


def insert_in_db(result):
    table = init_transitory_daily_collection(db_name)
    _list = []
    for i in result:
        result[i]['_id'] = i
        _list.append(result[i])
        if len(_list) > 10000:
            table.insert_many(_list)
            _list = []
    if len(_list) > 0:
        table.insert_many(_list)
        _list = []
    table.rename(get_daily_collection_name(db_name))
    log.debug(f'FINISH INSERT IN COLLECTION {table.name}')


def inner_main():
    txt_path = download_new_file()
    o = process_data(txt_path)
    insert_in_db(o)


def main(error_callback):
    try:
        inner_main()
    except Exception as e:
        error_callback(e, 'download_asRank_files')


if __name__ == '__main__':
    main(exception_happen)
