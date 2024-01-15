from datetime import datetime
import json
from pymongo import MongoClient
from utils.config_util import get_config

db_config = get_config('db_config')
print(db_config)
print(get_config('forever_start_datetime'))
db_name = db_config['db_name']
legal_moas_db = 'hijack-2022'
host = db_config['host']
port = db_config['port']
user = db_config['user']
pwd = db_config['pwd']
transitory_name = 'transitory_name'

collection_name_mapping = {
    'serial1': {
        'db_name': 'caida-as-relationships',
        'collection_name': lambda date: date,
        # 'date_format': "%Y%m%d",
        'col-date_format': "%Y%m%d",
    },
    'irr_WHOIS':{
        'db_name': 'irr_whois',
        'collection_name': 'WHOIS',
        # 'date_format': "%Y-%m-%d",
        'col-date_format': "WHOIS-%Y-%m-%d"
    },
    'irr_DOMAIN':{
        'db_name': 'irr_whois',
        'collection_name': 'DOMAIN',
        # 'date_format': "%Y-%m-%d",
        'col-date_format': "DOMAIN"
    },
        'as_info': {
        'db_name': 'as_info',
        'collection_name': lambda date: date,
        # 'date_format': "%Y-%m-%d",
        'col-date_format': "%Y-%m-%d",
    },
        'roa-db-2023': {
        'db_name': 'ROA-DB',
        'collection_name': lambda date: f'roa-db',
        'col-date_format': "roa-db-%Y-%m-%d",
    },
    'roa-db2-2023': {
        'db_name': 'ROA-DB2',
        'collection_name': lambda date: f'roa-db',
        'col-date_format': "roa-db-%Y-%m-%d",
    },
        'DOMAIN': {
        'db_name': 'irr_whois',
        'collection_name': 'DOMAIN',
        # 'date_format': "%Y-%m-%d",
        'col-date_format': "DOMAIN"
    },
}
this_mongo_client = MongoClient(host=host, port=int(port),username=user, password=pwd, unicode_decode_error_handler='ignore', maxPoolSize=1024, connect=False)

def create_mongo_client():
    return MongoClient(host=host, port=int(port),username=user, password=pwd, unicode_decode_error_handler='ignore', maxPoolSize=1024, connect=False)

def get_mongo_db():
    _mongo_client = MongoClient(host=host, port=int(port),username=user, password=pwd, unicode_decode_error_handler='ignore', maxPoolSize=1024, connect=False)
    db = _mongo_client[db_name]
    return db

def get_legal_moas_mongo_db():
    legal_db = this_mongo_client[legal_moas_db]
    return legal_db


gol_legal_db = get_legal_moas_mongo_db()
gol_db = get_mongo_db()
ROA_DB = 'ROA-DB'

collection_dict = {
    'possible-hijack': 'possible-hijack',
    'moas': 'moas',
    'sub-possible-hijack': 'sub-possible-hijack',
    'sub-moas':'sub-moas',
    'ongoing_hijack':'ongoing_hijack',
    'ongoing_moas':'ongoing_moas',
    'ongoing_subhijack':'ongoing_subhijack',
    'ongoing_submoas':'ongoing_submoas',
}

ongoing_collection = ['ongoing_hijack','ongoing_moas','ongoing_subhijack','ongoing_submoas']

for c_name in collection_dict.values():
    gol_db[c_name].create_index([('start_timestamp', -1)])

gol_db['ongoing_hijack'].create_index([('prefix', 1)], unique=True ,background=True)
gol_db['ongoing_moas'].create_index([('prefix', 1)], unique=True ,background=True)

gol_db['ongoing_subhijack'].create_index([('prefix', 1),('subprefix', 1)], unique=True ,background=True)
gol_db['ongoing_submoas'].create_index([('prefix', 1),('subprefix', 1)], unique=True ,background=True)


def get_collection_by_name(name, db):
    return db[collection_dict[name]]


def get_daily_collection_name(db_mapping_name):
    will_use_collection_name = datetime.utcnow().strftime(collection_name_mapping[db_mapping_name]['col-date_format'])
    return will_use_collection_name


def get_collection_by_timestamp2(db_mapping_name,_ts):
    will_use_collection_name = datetime.utcfromtimestamp(_ts).strftime(collection_name_mapping[db_mapping_name]['col-date_format'])
    return this_mongo_client[collection_name_mapping[db_mapping_name]['db_name']][will_use_collection_name]


def get_collection_by_timestamp(db_mapping_name,ts,mongo_client=this_mongo_client):
    existColName = mongo_client[collection_name_mapping[db_mapping_name]['db_name']].list_collection_names()
    match_list = []
    for i in existColName:
        try:
            datetime.strptime(i, collection_name_mapping[db_mapping_name]['col-date_format'])
            match_list.append(i)
        except ValueError:
            continue
    match_list.sort(key=lambda x: datetime.strptime(x, collection_name_mapping[db_mapping_name]['col-date_format']).timestamp())
    will_use_collection_name = datetime.utcfromtimestamp(int(ts)).strftime(collection_name_mapping[db_mapping_name]['col-date_format'])
    if will_use_collection_name not in match_list:
        will_use_collection_name = match_list[-1]
    return mongo_client[collection_name_mapping[db_mapping_name]['db_name']][will_use_collection_name]


def get_daily_collection(db_mapping_name,mongo_client=this_mongo_client):
    existColName = mongo_client[collection_name_mapping[db_mapping_name]['db_name']].list_collection_names()
    match_list = []
    for i in existColName:
        try:
            datetime.strptime(i, collection_name_mapping[db_mapping_name]['col-date_format'])
            match_list.append(i)
        except ValueError:
            continue
    match_list.sort(key=lambda x: datetime.strptime(x, collection_name_mapping[db_mapping_name]['col-date_format']).timestamp())
    if len(match_list) != 0:    
        will_use_collection_name = match_list[-1]
    else:
        will_use_collection_name = get_daily_collection_name(db_mapping_name)
    return mongo_client[collection_name_mapping[db_mapping_name]['db_name']][will_use_collection_name]

def match_roa_col_by_ts(ts,mongo_client=this_mongo_client):
    will_use_collection_name = datetime.utcfromtimestamp(int(ts)).strftime(collection_name_mapping['roa-db-2023']['col-date_format'])
    col_list = mongo_client[ROA_DB].list_collection_names()
    if will_use_collection_name in col_list:
        return True
    else:
        return False

def get_roa_col_by_ts(ts,mongo_client=this_mongo_client):
    will_use_collection_name = datetime.utcfromtimestamp(int(ts)).strftime(collection_name_mapping['roa-db-2023']['col-date_format'])
    return mongo_client[ROA_DB][will_use_collection_name]


def init_transitory_daily_collection(db_mapping_name):
    if transitory_name in this_mongo_client[collection_name_mapping[db_mapping_name]['db_name']].list_collection_names():
        this_mongo_client[collection_name_mapping[db_mapping_name]['db_name']][transitory_name].drop()
    return this_mongo_client[collection_name_mapping[db_mapping_name]['db_name']][transitory_name]

def get_today_collection(db_mapping_name):
    will_use_collection_name = datetime.utcnow().strftime(collection_name_mapping[db_mapping_name]['col-date_format'])
    # will_use_collection_name = collection_name_mapping[db_mapping_name]['collection_name'](date)
    return this_mongo_client[collection_name_mapping[db_mapping_name]['db_name']][will_use_collection_name]



class MyCollection:
    def __init__(self, db_mapping_name):
        self.mapping_name = db_mapping_name

        self.client = this_mongo_client
        if 'conn' in collection_name_mapping[db_mapping_name]:
            self.client = collection_name_mapping[db_mapping_name]['conn']

        self.db_name = collection_name_mapping[db_mapping_name]['db_name']
        self.col_name = datetime.utcnow().strftime(collection_name_mapping[db_mapping_name]['col-date_format'])
        self.col = self.client[self.db_name][f'{self.col_name}-{transitory_name}']

    def insert_many(self, *args, **kwargs):
        self.col.insert_many(*args, **kwargs)

    def create_index(self, *args, **kwargs):
        self.col.create_index(*args, **kwargs)

    def finish(self):
        self.col.rename(self.col_name, dropTarget=True)



def get_my_collection(db_mapping_name):
    return MyCollection(db_mapping_name)