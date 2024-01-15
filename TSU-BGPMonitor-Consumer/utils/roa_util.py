import requests
import ipaddress
from datetime import datetime
from utils.common_util import exception_happen
from utils.log_util import get_logger
from utils.manager_util import get_manager
from utils.config_util import get_config
from utils.mongo_util import match_roa_col_by_ts,get_roa_col_by_ts

manager = get_manager()
roa_url = get_config('roa_url')
roa_cache = manager.dict()
NOT_EXISTS = -1
EXPIRE_TS = 300

def get_from_cache(key):
    expire_key = f'{key}_expire'
    if key in roa_cache:
        if expire_key in roa_cache:
            if datetime.now().timestamp() > roa_cache[expire_key]:
                del roa_cache[expire_key]
                del roa_cache[key]
            else:
                return roa_cache[key]
        else:
            del roa_cache[key]
    return NOT_EXISTS

def set_in_cache(key,value):
    expire_key = f'{key}_expire'
    expire_ts = datetime.now().timestamp() + EXPIRE_TS
    roa_cache[key] = value
    roa_cache[expire_key] = expire_ts
    

def ip_to_binary(prefix):
    # 如果是IPv4地址
    ip_address,p = prefix.split('/')
    if '.' in ip_address:
        # 将IPv4地址转换为32位二进制
        binary_ip = bin(int(''.join(['{:08b}'.format(int(octet)) for octet in ip_address.split('.')]), 2))[2:]
        # 补全32位
        binary_ip = '4|'+'0' * (32 - len(binary_ip)) + binary_ip
    # 如果是IPv6地址
    else:
        # 将IPv6地址转换为128位二进制
        binary_ip = bin(int(''.join(['{:04x}'.format(int(octet, 16)) for octet in ip_address.split(':')]), 16))[2:]
        # 补全128位
        binary_ip = '6|'+'0' * (128 - len(binary_ip)) + binary_ip
    return binary_ip



def match_in_roa(prefix,asn,ts,mongo_client) -> bool:
    
    log = get_logger()
    key = f'{prefix}_{asn}'
    expire_key = f'{key}_expire'
    result = get_from_cache(key)
    if result is not NOT_EXISTS:
        log.debug(f"Match ROA in Cache {key}, Expire ts:{roa_cache[expire_key]} {ts} {result}")
        return result
        
    if match_roa_col_by_ts(int(ts),mongo_client):
        try:
            roa_col = get_roa_col_by_ts(int(ts),mongo_client)
            log.debug(f"[ROA] USE DB!")
            ts = int(ts)
            ts -= (ts%300)
            bin_prefix = ip_to_binary(ipaddress.ip_network(prefix).exploded)
            bin_prefix_len = len(bin_prefix)
            condition = {'timestamp': {'$gte':ts}, 'binary_prefix': {'$in': [bin_prefix[:ii] for ii in range(bin_prefix_len, 0, -1)]}, 'asn': asn}
            if roa_col.find_one(condition):
                set_in_cache(key,True)
                return True
        except Exception as e:
            log.error(f'{prefix},{asn},{ts}')
            log.error(e)
        set_in_cache(key,False)
        return False
    else:
        log.debug(f"[ROA] USE API!")
        url = roa_url.format(**{'asn':asn,'prefix':prefix})
        try:
            response = requests.get(url)
            if response.status_code == 200:
                data = response.json()
                log.debug(f"{prefix} {asn} {ts} {data['validated_route']['validity']}")
                state = data['validated_route']['validity']['state']
                if state == 'valid':
                # self.log.debug(data)
                    set_in_cache(key,True)
                    return True
                set_in_cache(key,False)
                return False
        except Exception as e:
            exception_happen(e)
