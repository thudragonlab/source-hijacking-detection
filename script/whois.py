import ipaddress
import os
import re
import copy
from multiprocessing.pool import ThreadPool

from pymongo import IndexModel

from utils.mongo_util import init_transitory_daily_collection, get_daily_collection_name
from utils.common_util import download_by_ftp,exception_happen,ip_to_binary
from utils.log_util import get_logger,LOG_NAME
from utils.config_util import get_config

log = get_logger(LOG_NAME.WHOIS)

whois_keys = ['aut-num', 'as-name', 'import', 'default', 'export', 'admin-c', 'tech-c', 'inet-rtr', 'mnt-by', 'changed', 'source', 'as-set', 'descr'
    , 'members', 'route', 'route6', 'origin', 'remarks', 'mntner', 'upd-to', 'mnt-nfy', 'auth', 'notify', 'inetnum', 'inet6num', 'mnt-lower',
              '*xxte6', '*xxte']

APNIC_PATH = 'ftp.apnic.net'
RIPE_PATH = 'ftp.ripe.net'
ARIN_PATH = 'ftp.arin.net'
LACNIC_PATH = 'ftp.lacnic.net'
AFRINIC_PATH = 'ftp.afrinic.net'
RADB_PATH = 'ftp.radb.net'

TMP_PATH = f'{os.getcwd()}/{get_config("tmp_name")}'
os.makedirs(TMP_PATH,exist_ok=True)

class Whois:
    def __init__(self):
        pass


def split_ip_block(w):
    inetnum = w.__getattribute__('inetnum')
    min_ip, max_ip = inetnum.split('-')
    min_ip_num = int(ip_to_binary(min_ip.strip()), 2)
    max_ip_num = int(ip_to_binary(max_ip.strip()), 2)
    w.__setattr__('min_ip_num', min_ip_num)
    w.__setattr__('max_ip_num', max_ip_num)


def read_and_insert_data(file_name, regex, collection):
    my_list = []
    re_cimpile = re.compile(regex)
    with open(file_name, 'r', errors='ignore') as f:

        w = Whois()
        attr_k = ''
        attr_v = ''
        while True:
            i = f.readline()
            if not i:
                break
            if i[0] == '#' or i == 'EOF':
                continue
            if i == '\n':
                if attr_k:
                    if hasattr(w, 'inetnum'):
                        split_ip_block(w)
                    if hasattr(w, 'as-block'):
                        for nw in split_as_block(w):
                            nd = nw.__dict__
                            nd['attr_len'] = len(nd)
                            my_list.append(nd)

                    wd = w.__dict__
                    wd['attr_len'] = len(wd)
                    my_list.append(wd)
                    if len(my_list) >= 10000:
                        collection.insert_many(my_list)
                        log.info(f'Insert 10000 WHOIS data, Last data is {my_list[-1]}')
                        my_list = []
                    w = Whois()
            else:
                i_s = re_cimpile.split(i)
                # print(i_s)
                if len(i_s) == 2:
                    k, v = i_s

                    attr_k = k.strip()
                    attr_v = v.strip()
                    if attr_v == 'DUMY-RIPE':
                        continue
                    if attr_k == 'source':
                        attr_v = attr_v.upper()
                    if attr_k == '*xxte':
                        attr_k = 'route'
                    if attr_k == '*xxte6':
                        attr_k = 'route6'
                    if attr_k == 'route' or attr_k == 'route6':
                        try:
                            attr_v = ipaddress.ip_network(attr_v).exploded
                            w.__setattr__('binary', ip_to_binary(attr_v.split('/')[0]))
                        except Exception as e:
                            log.error(e)
                            pass

                    if attr_k == 'origin':
                        asn_regex = r"(?P<asn>^AS\d+).*"
                        asn_pattern = re.search(asn_regex, attr_v)
                        if asn_pattern:
                            attr_v = asn_pattern.group('asn')

                    if hasattr(w, attr_k):
                        # 如果已经有attr,并且只有一个value
                        if type(w.__getattribute__(attr_k)) == str:
                            # value转list
                            setattr(w, attr_k, [w.__getattribute__(attr_k)])

                        # 新的value加入list中
                        if type(w.__getattribute__(attr_k)) == list:
                            w.__getattribute__(attr_k).append(attr_v)
                    else:
                        setattr(w, attr_k, attr_v)
                elif len(i_s) == 1:

                    attr_v = i_s[0].strip()
                    a_v_s = attr_v.split(':', 1)
                    # print(a_v_s)
                    if len(a_v_s) == 2:
                        k, v = a_v_s
                        if not hasattr(w, attr_k):
                            if k in whois_keys:
                                setattr(w, k, v)
                            continue

                    if type(w.__getattribute__(attr_k)) == str:
                        w.__setattr__(attr_k, f'{w.__getattribute__(attr_k)}\n{str(attr_v)}')
                    elif type(w.__getattribute__(attr_k)) == list:
                        attr_list = w.__getattribute__(attr_k)
                        attr_list[-1] = f'{attr_list[-1]}\n{attr_v}'

    if len(my_list) > 0:
        collection.insert_many(my_list)
        log.info(f'Insert rest WHOIS data, Last data is {my_list[-1]}')
        my_list = []


def split_as_block(w):
    as_block = w.__getattribute__('as-block')
    if len(as_block) > 20:
        return []
    # print(as_block)
    start_as, end_as = as_block.split('-')
    start_as = start_as.strip()[2:]
    end_as = end_as.strip()[2:]

    for _as in range(int(start_as), int(end_as) + 1):
        cw = copy.copy(w)
        cw.__setattr__('aut-num', f'AS{_as}')
        yield cw


def process_afrinic_data(file_name, __col):
    try:
        read_and_insert_data(file_name, re.compile(': '), __col)
    except Exception as e:
        log.error(e)


def process_arin_data(file_name, __col):
    try:

        read_and_insert_data(file_name, re.compile(': |:\t|:\n'), __col)
    except Exception as e:
        log.error(e)


def process_ripe_data(file_name, __col):
    try:

        read_and_insert_data(file_name, re.compile(': |:\t|:\n'), __col)
    except Exception as e:
        log.error(e)


def process_lacnic_data(file_name, __col):
    try:
        read_and_insert_data(file_name, re.compile(': |:\t|:\n'), __col)
    except Exception as e:
        log.error(e)


def process_apnic_data(file_name, __col):
    try:
        read_and_insert_data(file_name, re.compile(': |:\t|:\n'), __col)
    except Exception as e:
        log.error(e)


def process_radb_data(file_name, __col):
    try:
        read_and_insert_data(file_name, re.compile(': |:\t|:\n'), __col)
    except Exception as e:
        log.error(e)


def process_afrinic(_col):
    url = 'ftp.afrinic.net/pub/dbase/afrinic.db.gz'
    dst_path = download_by_ftp(url, TMP_PATH)
    os.system(f'gzip -dc {dst_path} > {dst_path}.txt')
    decompression_filename = f'{dst_path}.txt'
    process_afrinic_data(decompression_filename, _col)
    if dst_path:
        os.remove(dst_path)
        os.remove(f'{dst_path}.txt')


def process_arin(_col):
    url = 'ftp.arin.net/pub/rr/arin.db.gz'
    dst_path = download_by_ftp(url, TMP_PATH)
    os.system(f'gzip -dc {dst_path} > {dst_path}.txt')
    decompression_filename = f'{dst_path}.txt'
    process_arin_data(decompression_filename, _col)
    if dst_path:
        os.remove(dst_path)
        os.remove(f'{dst_path}.txt')


def process_ripe(_col, url):
    dst_path = download_by_ftp(url, TMP_PATH)
    os.system(f'gzip -dc {dst_path} > {dst_path}.txt')
    decompression_filename = f'{dst_path}.txt'
    process_ripe_data(decompression_filename, _col)
    if dst_path:
        os.remove(dst_path)
        os.remove(f'{dst_path}.txt')


def process_lacnic(_col):
    url = 'ftp.lacnic.net/lacnic/irr/lacnic.db.gz'
    dst_path = download_by_ftp(url, TMP_PATH)
    os.system(f'gzip -dc {dst_path} > {dst_path}.txt')
    decompression_filename = f'{dst_path}.txt'
    process_lacnic_data(decompression_filename, _col)
    if os.path.exists(dst_path):
        os.remove(dst_path)
        os.remove(f'{dst_path}.txt')


def process_apnic(_col, url):
    dst_path = download_by_ftp(url, TMP_PATH)
    os.system(f'gzip -dc {dst_path} > {dst_path}.txt')
    decompression_filename = f'{dst_path}.txt'
    process_apnic_data(decompression_filename, _col)
    if dst_path:
        os.remove(dst_path)
        os.remove(f'{dst_path}.txt')


def process_radb(_col, url):
    dst_path = download_by_ftp(url, TMP_PATH)
    os.system(f'gzip -dc {dst_path} > {dst_path}.txt')
    decompression_filename = f'{dst_path}.txt'
    process_radb_data(decompression_filename, _col)
    if dst_path:
        os.remove(dst_path)
        os.remove(f'{dst_path}.txt')


def inner_main(error_callback):
    tp = ThreadPool(10)
    db_mapping_name = 'irr_WHOIS'


    decompression_filename_list = []
    for url in [f'{APNIC_PATH}/pub/apnic/whois/apnic.db.organisation.gz', f'{APNIC_PATH}/pub/apnic/whois/apnic.db.as-set.gz',
                f'{APNIC_PATH}/pub/apnic/whois/apnic.db.mntner.gz', f'{APNIC_PATH}/pub/apnic/whois/apnic.db.role.gz',
                f'{APNIC_PATH}/pub/apnic/whois/apnic.db.as-block.gz', f'{APNIC_PATH}/pub/apnic/whois/apnic.db.irt.gz',
                f'{APNIC_PATH}/pub/apnic/whois/apnic.db.route.gz', f'{APNIC_PATH}/pub/apnic/whois/apnic.db.route6.gz',
                f'{APNIC_PATH}/pub/apnic/whois/apnic.db.aut-num.gz', f'{APNIC_PATH}/pub/apnic/whois/apnic.db.inet6num.gz',
                f'{APNIC_PATH}/pub/apnic/whois/apnic.db.inetnum.gz',

                f'{RIPE_PATH}/ripe/dbase/split/ripe.db.route6.gz', f'{RIPE_PATH}/ripe/dbase/split/ripe.db.route.gz',
                f'{RIPE_PATH}/ripe/dbase/split/ripe.db.aut-num.gz', f'{RIPE_PATH}/ripe/dbase/split/ripe.db.inet6num.gz',
                f'{RIPE_PATH}/ripe/dbase/split/ripe.db.as-set.gz', f'{RIPE_PATH}/ripe/dbase/split/ripe.db.irt.gz',
                f'{RIPE_PATH}/ripe/dbase/split/ripe.db.mntner.gz', f'{RIPE_PATH}/ripe/dbase/split/ripe.db.organisation.gz',
                f'{RIPE_PATH}/ripe/dbase/split/ripe.db.person.gz', f'{RIPE_PATH}/ripe/dbase/split/ripe.db.role.gz',
                f'{RIPE_PATH}/ripe/dbase/split/ripe.db.inetnum.gz', f'{RIPE_PATH}/ripe/dbase/split/ripe.db.as-block.gz',
                #
                f'{ARIN_PATH}/pub/rr/arin.db.gz',
                f'{LACNIC_PATH}/lacnic/irr/lacnic.db.gz',
                f'{AFRINIC_PATH}/pub/dbase/afrinic.db.gz',
                #
                f'{RADB_PATH}/radb/dbase/altdb.db.gz',
                f'{RADB_PATH}/radb/dbase/arin.db.gz',
                f'{RADB_PATH}/radb/dbase/bboi.db.gz',
                f'{RADB_PATH}/radb/dbase/bell.db.gz',
                f'{RADB_PATH}/radb/dbase/canarie.db.gz',
                f'{RADB_PATH}/radb/dbase/jpirr.db.gz',
                f'{RADB_PATH}/radb/dbase/level3.db.gz',
                f'{RADB_PATH}/radb/dbase/nestegg.db.gz',
                f'{RADB_PATH}/radb/dbase/nttcom.db.gz',
                f'{RADB_PATH}/radb/dbase/panix.db.gz',
                f'{RADB_PATH}/radb/dbase/radb.db.gz',
                f'{RADB_PATH}/radb/dbase/reach.db.gz',
                f'{RADB_PATH}/radb/dbase/tc.db.gz'
                ]:
        tp.apply_async(download_file, (decompression_filename_list, url,), error_callback=error_callback)

    tp.close()
    tp.join()

    col = init_transitory_daily_collection(db_mapping_name)
    col.create_indexes(
        [IndexModel([('route', 1), ('origin', 1)], background=True, sparse=True),
         IndexModel([('route6', 1), ('origin', 1)], background=True, sparse=True),
         IndexModel([('aut-num', 1)], background=True, sparse=True),
         IndexModel([('inetnum', 1)], background=True, sparse=True),
         IndexModel([('binary', 1)], background=True, sparse=True),
         IndexModel([('local-as', 1), ('peer', 1)], background=True, sparse=True),
         IndexModel([('irt', 1)], background=True, sparse=True),
         IndexModel([('nic-hdl', 1)], background=True, sparse=True),
         IndexModel([('inet6num', 1)], background=True, sparse=True)])

    for decompression_filename in decompression_filename_list:
        if APNIC_PATH in decompression_filename:
            process_apnic_data(decompression_filename, col)
        elif RIPE_PATH in decompression_filename:
            process_ripe_data(decompression_filename, col)
        elif ARIN_PATH in decompression_filename:
            process_arin_data(decompression_filename, col)
        elif LACNIC_PATH in decompression_filename:
            process_lacnic_data(decompression_filename, col)
        elif AFRINIC_PATH in decompression_filename:
            process_afrinic_data(decompression_filename, col)
        elif RADB_PATH in decompression_filename:
            process_radb_data(decompression_filename, col)

        if os.path.exists(decompression_filename):
            os.remove(decompression_filename)

    
    col.rename(get_daily_collection_name(db_mapping_name))


def download_file(decompression_filename_list, url):
    dst_path = download_by_ftp(url, TMP_PATH)
    domain = url.split('/')[0]
    if not dst_path:
        return
    decompression_filename = f'{dst_path}.txt'
    os.system(f'gzip -dc {dst_path} > {decompression_filename}')
    if os.path.exists(dst_path):
        os.remove(dst_path)
    decompression_filename_list.append(decompression_filename)
    print(decompression_filename_list)


def main(error_callback):
    try:
        inner_main(error_callback)
    except Exception as e:
        error_callback(e, 'download_whois_data')


if __name__ == '__main__':
    # ARIN,RIPE,APNIC,LACNIC,AFRINIC
    inner_main(exception_happen)
