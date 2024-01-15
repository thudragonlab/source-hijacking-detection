import csv
import re
import os
import ipaddress
import socket
import time
import traceback
from datetime import datetime
from typing import List
import numpy
from multiprocessing.pool import ThreadPool
import multiprocessing
import json
import random
import resource
import json
from tqdm import tqdm
from utils.mongo_util import get_my_collection
import sys
from utils.common_util import download_file,exception_happen
from utils.config_util import get_config

TMP_PATH = f'{os.getcwd()}/{get_config("tmp_name")}'

DNS_NUM = 10


def ip_to_binary(ip_address):
    # 如果是IPv4地址
    if '.' in ip_address:
        # 将IPv4地址转换为32位二进制

        binary_ip = bin(int(''.join(['{:08b}'.format(int(octet)) for octet in ip_address.split('.')]), 2))[2:]
        # 补全32位
        binary_ip = '0' * (32 - len(binary_ip)) + binary_ip
    # 如果是IPv6地址
    else:
        # 将IPv6地址转换为128位二进制

        binary_ip = bin(int(''.join(['{:04x}'.format(int(octet, 16)) for octet in ipaddress.IPv6Address(ip_address).exploded.split(':')]), 16))[2:]
        # 补全128位
        binary_ip = '0' * (128 - len(binary_ip)) + binary_ip
    return binary_ip


DNS_regex = re.compile(r'^Server.*?(\b\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}\b|\b[0-9a-fA-F:]+\b)')
ip_address_regex = re.compile(r'^Address:(\t|\s)(\b\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}\b|\b[0-9a-fA-F:]+\b)$')

danger_list = ['newtrendmicro.com']


def generate_supernet_regex(prefix: str) -> List[str]:
    addr = ipaddress.ip_network(prefix)
    _list = []
    for i in range(0, addr.prefixlen + 1 - 8):
        _list.append(addr.supernet(i).exploded)
    return _list


def do_something():
    # soft_limit, hard_limit = resource.getrlimit(resource.RLIMIT_NPROC)
    # resource.setrlimit(resource.RLIMIT_NPROC, (soft_limit * 2, hard_limit * 2))
    # soft_limit, hard_limit = resource.getrlimit(resource.RLIMIT_NPROC)
    max_thread_qsize = 10
    # as_domain_map = manager.dict()
    # lock = manager.Lock()

    # l = ['acesso.com', 'myfritz.net', 'msedge.net', 'google.com', 'baidu.com', 'european-voice.com', 'cloudflare.com', 'akamai.net', 'zhihu.com',
    #      'googlevideo.com', 'bing.com', 'github.com', 'acesso.com', 'myfritz.net', 'msedge.net', 'google.com', 'baidu.com', 'european-voice.com',
    #      'cloudflare.com', 'akamai.net', 'zhihu.com', 'googlevideo.com', 'bing.com', 'github.com', 'acesso.com', 'myfritz.net', 'msedge.net',
    #      'google.com', 'baidu.com', 'european-voice.com', 'cloudflare.com', 'akamai.net', 'zhihu.com', 'googlevideo.com', 'bing.com', 'github.com',
    #      'acesso.com', 'myfritz.net', 'msedge.net', 'google.com', 'baidu.com', 'european-voice.com', 'cloudflare.com', 'akamai.net', 'zhihu.com',
    #      'googlevideo.com', 'bing.com', 'github.com']
    l = []
    tranco_path = f'{TMP_PATH}/tranco_827VV.csv'
    tranco_path = download_file('https://tranco-list.eu/download/QGNN4/full', tranco_path)
    with open(tranco_path, 'r') as f:
        for iii in csv.reader(f):
            if iii[1] in danger_list:
                continue
            l.append(iii[1])

    # with open(f'{TMP_PATH}/cloudflare-radar-domains-top-1000000.csv', 'r') as f:
    #     for iii in csv.reader(f):
    #         if iii[0] in danger_list:
    #             continue
    #         l.append(iii[0])

    pp = multiprocessing.Pool(multiprocessing.cpu_count())
    # _l = l[0:10000]
    _l = l
    offset = numpy.ceil((len(_l) / multiprocessing.cpu_count()))
    for ii in range(multiprocessing.cpu_count()):
        # for domain in _l:
        # solve_domain(_l,ii,max_thread_qsize)
        pp.apply_async(solve_domain, (_l[int(ii * offset): int((ii + 1) * offset)], ii, max_thread_qsize,), error_callback=exception_happen)
    #
    pp.close()
    pp.join()

    as_l = []


def solve_domain(domain_list, index, max_thread_qsize):
    tp = ThreadPool((multiprocessing.cpu_count()) * 9)
    c = {'count': 0}
    # tl = threading.Lock()
    dns_servers = [
        '',
        '8.8.8.8',  # Google DNS
        # '8.8.4.4',  # Google DNS
        '1.1.1.1',  # Cloudflare DNS
        # '1.0.0.1',  # Cloudflare DNS
        '208.67.222.222',  # OpenDNS
        # '208.67.220.220',  # OpenDNS
        '9.9.9.9',  # Quad9 DNS
        # '149.112.112.112',  # Quad9 DNS
        '209.244.0.3',  # Level3 DNS
        # '209.244.0.4',  # Level3 DNS
        '199.85.126.10',  # Norton DNS
        # '199.85.127.10',  # Norton DNS
        '8.26.56.26',  # Comodo Secure DNS
        # '8.20.247.20',  # Comodo Secure DNS
        '84.200.69.80',  # DNS.WATCH
        # '84.200.70.40',  # DNS.WATCH
        '77.88.8.8',  # Yandex DNS
        # '77.88.8.1',  # Yandex DNS
        '94.140.14.14',  # AdGuard DNS
        # '94.140.15.15'  # AdGuard DNS
    ]
    dlen = len(domain_list) * len(dns_servers)
    count = 0
    # def wait_for_qsize:
    # tp._inqueue.qsize()
    for domain in domain_list:
        for dns in dns_servers:

            while count - c['count'] > max_thread_qsize:
                time.sleep(10)

            tp.apply_async(do_nslookup, (domain, dns, index, dlen, c, tp,), error_callback=exception_happen)
            count += 1

    tp.close()
    tp.join()


def do_nslookup(domain, dns, index, dlen, ccc, tp):
    cmd = f'nslookup -timeout=1 {domain} {dns}'
    o = {'dns': dns, 'binary_ip': '-', 'domain': domain}
    r = random.randint(0, 9)
    if r > 5:
        time.sleep(0.1)
    with os.popen(cmd) as res:
        ll = res.readlines()

        if 'timed out' not in ''.join(ll):
            for c in ll:

                if ip_address_regex.match(c):
                    bip = ip_to_binary(ip_address_regex.match(c).group(2))
                    o['binary_ip'] = bip
                    # dmap[domain][bip] = domain

    with open(f'{TMP_PATH}/dmap{index}.jsonl', 'a+') as f:
        f.write(f'{json.dumps(o)}\n')
    ccc['count'] += 1
    print(f'[{index}] {ccc["count"]}/{dlen} {tp._inqueue.qsize()} ({domain})')



def save_in_db(_local_path):
    _list = []
    col.create_index([('binary_ip', 1)], background=True)
    with open(_local_path,'r') as f:
        data = f.readlines()
        line_count = len(data)

    with tqdm(total=line_count) as bar:
        for i in data:
            i = json.loads(i.strip())
            bar.update()
            _list.append(i)
            if len(_list) >= 10000:
                col.insert_many(_list)
                _list = []
        if len(_list) > 0:
            col.insert_many(_list)
            _list = []


def download_file2(dmap_list):
    for _local_path in dmap_list:
        local_path = f'{TMP_PATH}/{_local_path}'
        # print(f'{TMP_PATH}/{_local_path}')
        save_in_db(local_path)



if __name__ == '__main__':
    start = datetime.now()
    # do_something()
    col = get_my_collection('DOMAIN')
    
    dmap_files_list =  list(filter(lambda x:'dmap' in x,os.listdir(f'{TMP_PATH}')))
    
    download_file2(dmap_files_list)
    # print(datetime.now() - start)
