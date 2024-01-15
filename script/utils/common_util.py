import ipaddress
import time
import traceback
import os
from datetime import datetime
import urllib3
import smtplib
from email.mime.text import MIMEText
from utils.config_util import get_config
from utils.log_util import LOG_NAME, get_logger
from ftplib import FTP
from tqdm import tqdm
import requests

from urllib3.util.retry import Retry
from requests.adapters import HTTPAdapter


mail_info = get_config('mail_info')
mail_pass = mail_info['mail_pass']
mail_host = mail_info['mail_host']
mail_user = mail_info['mail_user']
sender = mail_info['sender']


def getSession(retries=3, backoff_factor=0.5):
    session = requests.Session()
    retry_strategy = Retry(total=retries, backoff_factor=backoff_factor)
    adapter = HTTPAdapter(max_retries=retry_strategy)
    session.headers['Connection'] = 'keep-alive'
    session.mount('http://', adapter)
    session.mount('https://', adapter)
    return session


session = getSession()

urllib3.disable_warnings()

mail_pass = get_config('mail_pass')
server_name = get_config('server_name')
admin_email = get_config('admin_email')



def exception_happen(e,*args):

    # log = get_log()
    error_log = get_logger(LOG_NAME.ERROR_LOG)
    traceback.print_exception(type(e), e, e.__traceback__, file=open(LOG_NAME.ERROR_LOG_FILE_NAME.value, 'a+'))
    error_log.error(f'''
------------------------------------------
args:{args}
Exception Name:{e}
Exception Args:{e.args}
Exception Traceback{traceback.format_exc()}
------------------------------------------
    ''')
    # log.error(f'Exception Name:{e} , Exception Args:{e.args}')
    send_email(admin_email,f'''
    Server Name : {server_name}
    ------------------------------------------
    Exception Name:{e}
    Exception Args:{e.args}
    Exception Traceback{traceback.format_exc()}
    ------------------------------------------
        ''','Exception happened')



def timestamp2date(timestamp):
    return datetime.utcfromtimestamp(
        float(timestamp)).strftime("%Y-%m-%d %H:%M:%S")


def send_email(receivers, content, title, type='plain'):
    log = get_logger(LOG_NAME.ERROR_LOG)
    message = MIMEText(f'{content}', type, 'utf-8')
    message['Subject'] = title
    message['From'] = f'\"CGTF SEC\" <{sender}>'
    message['To'] = receivers
    try:
        smtpObj = smtplib.SMTP_SSL(mail_host)
        smtpObj.connect(mail_host, 465)
        smtpObj.login(mail_user, mail_pass)
        smtpObj.sendmail(
            sender, receivers, message.as_string())
        smtpObj.quit()
        print('send message to %s success' % receivers)
    except Exception as e:
        log.error(f'error , {e}' )  # 打印错误

def generate_supernet_regex(prefix: str):
    addr = ipaddress.ip_network(prefix)
    _list = []
    for i in range(0, addr.prefixlen + 1 - 8):
        _list.append(addr.supernet(i).exploded)
    return _list

def sec2readable(seconds):
    return '%d:%d:%d' % (seconds // 3600, seconds // 60 % 60, seconds % 60)


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
        binary_ip = bin(int(''.join(['{:04x}'.format(int(octet, 16)) for octet in ip_address.split(':')]), 16))[2:]
        # 补全128位
        binary_ip = '0' * (128 - len(binary_ip)) + binary_ip
    return binary_ip


def download_by_ftp(url, dst_path, ftp_port=21, loop_times=0):
    print(f'[DOWNLOAD] {url} save to {dst_path}, loop times -> {loop_times}')
    if loop_times > 5:
        return False
    try:
        url_s = url.split('/')
        target_file = url_s[-1]
        real_url = url_s[0]
        dst_target_file = f'{real_url}.{url_s[-1]}'
        dir_path = '/'.join(url_s[1:-1])

        # target_file = 'afrinic.db.gz'
        # 默认端口21
        # ftp_port = 21
        ftp = FTP()

        # 连接ftp
        ftp.connect(real_url, ftp_port)
        # ftp登录
        ftp.login()
        # 查看欢迎信息
        ftp.voidcmd('TYPE I')
        # print(ftp.getwelcome())
        ftp.cwd(dir_path)
        print(target_file)
        total = ftp.size(target_file)
        print(total)

        with open(os.path.join(dst_path, dst_target_file), 'wb') as f, tqdm(
                desc=target_file,
                total=total,
                unit='iB',
                unit_scale=True,
                unit_divisor=1024,
        ) as bar:
            def write(data):
                size = f.write(data)
                bar.update(size)

            ftp.retrbinary('RETR ' + target_file, write, 1 * 1024 * 1024)
        return os.path.join(dst_path, dst_target_file)
    except Exception as e:
        print(e)
        return download_by_ftp(url, dst_path, ftp_port=21, loop_times=loop_times + 1)


def download_file(url, file_dst_path, loop_times=0):
    print(f'[DOWNLOAD] {url} save to {file_dst_path}, loop times -> {loop_times}')
    if loop_times > 5:
        return False
    try:
        file_name = file_dst_path.split('/')[-1]
        with session.get(url, stream=True, timeout=60) as file_content:
            # content_size = int(file_content.headers['content-length'])
            data_count = int(file_content.headers.get('content-length', 0))
            local_file_size = -1
            if os.path.exists(file_dst_path):
                local_file_size = os.path.getsize(file_dst_path)
            if data_count != local_file_size:
                print(f'Download new gz file => {file_name}')
                with open(file_dst_path, 'wb') as file, tqdm(
                        desc=file_name,
                        total=data_count,
                        unit='iB',
                        unit_scale=True,
                        unit_divisor=1024,
                ) as bar:
                    for data in file_content.iter_content(chunk_size=1 * 1024 * 1024):
                        size = file.write(data)
                        bar.update(size)
    except Exception as e:
        print(e)
        time.sleep(5)
        download_file(url, file_dst_path, loop_times + 1)

    return file_dst_path
