from utils.log_util import  get_logger,LOG_NAME, make_log_queue
from utils.common_util import exception_happen
from utils.mongo_util import get_collection_by_name, gol_db, gol_legal_db,get_mongo_db
from utils.manager_util import get_lock, get_manager

from datetime import datetime

legal_moas_col_mname = 'legal_moas2'

manager = get_manager()

legal_moas = manager.dict()


def get_legal_moas():
    return legal_moas


def update_legal_moas(k, reason):
    global db
    db = get_mongo_db()
    if k not in legal_moas:
        lock = get_lock()
        with lock:
            if k in legal_moas:
                return
            # save in db
            # update dict
            
            col = db[legal_moas_col_mname]
            ks = k.split(' ')
            if len(ks) > 3:
                return
            as1,as2,prefix = ks
            o = {
                'k': k,
                'reason': reason,
                'ts': datetime.utcnow().timestamp()
            }
            if ' ' in prefix:
                p = None
                sp = None
                try:
                    sp,p = prefix.replace('_',' ').split(' ')
                except Exception as e:
                    exception_happen(e,prefix)
                    return 
                if p:
                    o['prefix'] = p
                if sp:
                    o['sub-prefix'] = sp
            else:
                if len(prefix) != 0:
                    o['prefix'] = prefix
            col.insert_one(o)
            legal_moas[k] = reason


def save_legal_moas(mongo_client=gol_db):
    '''
    存入数据库
    默认每隔两个小时（现实时间）自动存一次
    '''
    try:
        log = get_logger()
        temporary_name = 'legal_moas_temporary_name'
        mongo_client.drop_collection(temporary_name)
        log.debug(f'Drop old temporary legal moas collection')
        mongo_client.create_collection(temporary_name)
        col = mongo_client[temporary_name]
        data_list = []
        lock = get_lock()
        l_m = get_legal_moas()
        with lock:
            for k in l_m:
                o = {'_id': k, 'reason': l_m[k]}
                data_list.append(o)
                if len(data_list) > 5 * 10000:
                    col.insert_many(data_list)
                    log.debug(f'Save legal moas in db 50000 data')
                    data_list = []
            if len(data_list) > 0:
                col.insert_many(data_list)
                data_list = []
            log.debug(f'Save full legal moas in db')
            mongo_client.drop_collection(legal_moas_col_mname)
            log.debug(f'Drop old legal moas collection')
            col.rename(legal_moas_col_mname)
            log.debug(f'Rename new legal moas in db')
    except Exception as e:
        exception_happen(e)


def init_legal_moas():
    '''
    从数据库加载legal_moas
    '''
    try:
        log = get_logger()
        print('?')
        col = gol_legal_db[legal_moas_col_mname]
        legal_moas_data = col.find({})
        for i in legal_moas_data:
            legal_moas[i['k']] = i['reason']
        # if len(legal_moas) > 0:
        log.info(f'[INIT] Init legal moas, {len(legal_moas)} data in legal moas')
        # with open('legal_moas.log','w') as f:
        #     json.dump(legal_moas.copy(),f)
    except Exception as e:
        exception_happen(e)
