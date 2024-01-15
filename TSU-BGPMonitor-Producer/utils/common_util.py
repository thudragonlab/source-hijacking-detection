import ipaddress
import logging
import time
import json
import difflib
import os
import sys, traceback
from datetime import datetime
from tqdm import tqdm
import io
import subprocess
from string import Template
import math
import requests
from lxml import html
import urllib3
import smtplib
from email.mime.text import MIMEText
from utils.config_util import get_config
from utils.log_util import LOG_NAME, get_logger
from urllib3.util.retry import Retry
from requests.adapters import HTTPAdapter
urllib3.disable_warnings()


server_name = get_config('server_name')
server_name = get_config('admin_email')
admin_email = get_config('admin_email')
mail_info = get_config('mail_info')
mail_pass = mail_info['mail_pass']
mail_host = mail_info['mail_host']
mail_user = mail_info['mail_user']
sender = mail_info['sender']



def getSession(retries=3,backoff_factor=0.5):
    session = requests.Session()
    retry_strategy = Retry(total=retries, backoff_factor=backoff_factor)
    adapter = HTTPAdapter(max_retries=retry_strategy)
    session.headers['Connection'] = 'keep-alive'
    session.mount('http://', adapter)
    session.mount('https://', adapter)
    return session

session = getSession()

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
    ------------------------------------------
    Exception Name:{e}
    Exception Args:{e.args}
    Exception Traceback{traceback.format_exc()}
    ------------------------------------------
        ''','Exception happened')


def bgpdump_file(file_dst_path, txt_path,times = 0):
    if times > 5:
        exception_happen(Exception('bgpdump fail',file_dst_path,txt_path))
        return
    result = os.system(fr'bgpdump -m  {file_dst_path} >  {txt_path}')
    if result != 0:
         bgpdump_file(file_dst_path, txt_path,times + 1)


def bgpdump_file_popen(file_dst_path):
    process = subprocess.Popen(['bgpdump', '-m', file_dst_path], stdout=subprocess.PIPE, stderr=subprocess.STDOUT)
    return iter(process.stdout.readline,b'')

    


def timestamp2date(timestamp):
    return datetime.utcfromtimestamp(
        float(timestamp)).strftime("%Y-%m-%d %H:%M:%S")


def send_email(receivers, content, title, type='plain'):
    # 设置服务器所需信息
    # 163邮箱服务器地址
    # 设置email信息
    # 邮件内容设置
    message = MIMEText(f'Server Name : {server_name}\n{content}', type, 'utf-8')
    # 邮件主题
    message['Subject'] = title
    # 发送方信息
    message['From'] = sender
    # 接受方信息
    message['To'] = receivers

    # 登录并发送邮件
    try:
        smtpObj = smtplib.SMTP_SSL(mail_host)
        # 连接到服务器
        smtpObj.connect(mail_host, 465)
        # 登录到服务器
        smtpObj.login(mail_user, mail_pass)
        # 发送
        smtpObj.sendmail(
            sender, receivers, message.as_string())
        # 退出
        smtpObj.quit()
        print('send message to %s success' % receivers)
    except smtplib.SMTPException as e:
        print('error', e)  # 打印错误

def make_date_in_file_name(datetime_obj):
    return datetime_obj.strftime('%Y.%m'), datetime_obj.strftime('%Y%m%d.%H%M')


def get_latest_bview_online(timestamp,collector="rrc00"):
    log = get_logger(LOG_NAME.RUNNING_LOG)
    date_str, time_str = make_date_in_file_name(datetime.fromtimestamp(timestamp))
    url = f'https://data.ris.ripe.net/rrc00/{date_str}/bview.{time_str}.gz'
    cmd = f'curl {url}'
    print(url)
    while True:
        with os.popen(cmd,) as f:
            try:
                html = ''.join(f.readlines())
                if '404' in html:
                    print('Sleep 60s waiting for new bview.gz')
                    time.sleep(60)
                else:
                    break
            except Exception as e:
                log.error(e)
                break
    
    return url


def exception_happen_when_download(e, url, times,limit = 5):
    with open(LOG_NAME.ERROR_LOG_FILE_NAME.value, 'a+') as error_r:
        error_r.write(f'\n------------------------------------------\n')
        if times <= limit:
            error_r.write(f'Donwload {url} failed, retrying {times + 1} times\n')
        else:
            error_r.write(f'URL: Donwload {url} failed\n')
        error_r.write(f'Exception Date:{datetime.now()}\n')
        error_r.write(f'Exception Name:{e}\n')
        error_r.write(f'Exception Args:{e.args}\n')
        error_r.write(f'\n------------------------------------------\n')
        error_r.flush()
        send_email(admin_email,f'''
    ------------------------------------------
    Exception Name:{e}
    Exception Args:{e.args}
    Exception Traceback{traceback.format_exc()}
    ------------------------------------------
        ''','Exception happened')
        
        
def download(url,file_dst_path,loop_times=0):
    log = get_logger(LOG_NAME.RUNNING_LOG)
    log.debug(f'[DOWNLOAD] {url} save to {file_dst_path}, loop times -> {loop_times}')
    if loop_times > 5:
        # TODO Write URL, date, times
        return False
    try:
        
        file_name = file_dst_path.split('/')[-1]
        with session.get(url, stream=True, verify=False,timeout=60) as file_content:
        # content_size = int(file_content.headers['content-length'])
            data_count = int(file_content.headers.get('content-length', 0))
            local_file_size = os.path.getsize(file_dst_path) if os.path.exists(file_dst_path) else 0
            if data_count != local_file_size:
                print(f'Download new gz file => {file_name}')
                with open(file_dst_path, 'wb') as file, tqdm(
                        desc=file_name,
                        total=data_count,
                        unit='iB',
                        unit_scale=True,
                        unit_divisor=1024,
                ) as bar:
                    for data in file_content.iter_content(chunk_size=1024):
                        size = file.write(data)
                        bar.update(size)
    except Exception as e:
        exception_happen_when_download(e, url, loop_times)
        time.sleep(5)
        download(url,file_dst_path, loop_times + 1)

    return file_dst_path

