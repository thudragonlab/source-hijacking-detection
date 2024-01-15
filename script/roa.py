import ipaddress
from pkgutil import extend_path
import requests
from pymongo import IndexModel
from tqdm import tqdm
from utils.mongo_util import get_collection_by_timestamp2
from utils.common_util import download_file, ip_to_binary
import os
import csv

from datetime import datetime
from utils.config_util import get_config

# https://ftp.ripe.net/rpki/ripencc.tal/2023/08/01/roas.csv
# https://ftp.ripe.net/rpki/ripencc.tal/2023/08/02/roas.csv
# https://ftp.ripe.net/rpki/ripencc.tal/2023/08/31/roas.csv
TMP_PATH = f'{os.getcwd()}/{get_config("tmp_name")}'

if __name__ == '__main__':

    # Create roa collection 
    url = 'https://ftp.ripe.net/rpki/ripencc.tal/2023/01/01/roas.csv'
    d = datetime.strptime(url, 'https://ftp.ripe.net/rpki/ripencc.tal/%Y/%m/%d/roas.csv')
    now = d.timestamp()
    file_name = url.split('/')[-1]

    # from 2023-01-01 to 2023-01-10
    for i in range(10):
        url = datetime.utcfromtimestamp(now).strftime('https://ftp.ripe.net/rpki/ripencc.tal/%Y/%m/%d/roas.csv')
        dst = download_file(url, os.path.join(TMP_PATH, file_name))

        col = get_collection_by_timestamp2('roa-db2-2023', now)

        col.create_index([('timestamp', 1), ('binary_prefix', 1), ('asn', 1)], background=True)

        with open(dst, 'r') as f:
            data = csv.reader(f)
            next(data)
            list = []
            for ii in data:
                o = {}
                if len(ii) < 3:
                    continue
                asn = ii[1]
                prefix = ii[2]
                binary_prefix = ip_to_binary(ipaddress.ip_network(prefix).exploded.split('/')[0])
                o['prefix'] = prefix
                o['binary_prefix'] = binary_prefix
                o['timestamp'] = now
                o['asn'] = asn
                list.append(o)
            if len(list) > 0:
                col.insert_many(list)
        now += 86400
        print(col.name)

    # print(dst)
    # pass
