import ipaddress
import traceback
from datetime import datetime
import urllib3
import smtplib
from email.mime.text import MIMEText
from utils.config_util import get_config
from utils.log_util import LOG_NAME, get_logger
from string import Template
urllib3.disable_warnings()


server_name = get_config('server_name')
admin_email = get_config('admin_email')
mail_info = get_config('mail_info')
mail_pass = mail_info['mail_pass']
mail_host = mail_info['mail_host']
mail_user = mail_info['mail_user']
sender = mail_info['sender']



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
