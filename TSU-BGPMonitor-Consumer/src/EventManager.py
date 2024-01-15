import json
from collections import defaultdict
from queue import Queue
import os
from typing import List
from src.KnowledgeBase import get_as_country, knowledge_base
import src.HijackFilter as HijackFilter
import copy
import datetime
from utils.get_as_description import get_as_description
from utils.roa_util import match_in_roa
from utils.reason_util import Reason, get_reason
from utils.mongo_util import get_collection_by_name, get_mongo_db, create_mongo_client, get_today_collection
from utils.log_util import get_logger
from utils.common_util import  exception_happen, send_email, timestamp2date, sec2readable,ip_to_binary
from utils.aggregate_util import aggregate_subhijack_events,  aggregate_moas_events, aggregate_hijack_events, aggregate_submoas_events
from utils.config_util import get_config
import ipaddress
import requests

now = datetime.datetime.now()


class EventManager:
    # 事件管理器,提供事件管理功能，供检测系统调用
    def __init__(self, hash_0) -> None:
        self.lg_url = "http://203.91.121.211:11190/task_lg_random"  # 替换为实际的 API 地址
        self.bgpwatch_url = get_config('bgpwatch_url')
        self.running_moas_dict = {}
        self.running_submoas_dict = {}
        self.running_hijack_dict = {}
        self.running_subhijack_dict = {}  # key 为 pfx_superpfx 字符串
        self.submoas_super_dict = {}  # 用于标记该前缀是否处在submos当中，记录superpfx
        self.submoas_dict = {}  # 用于标记该前缀是否处在submos当中，记录subpfx
        self.victim_alarm_dict = {}
        self.finished_hijack_queue = Queue()
        self.finished_subhijack_queue = Queue()
        self.finished_moas_queue = Queue()
        self.finished_submoas_queue = Queue()
        self.max_moas_queue = 10  # 100
        self.max_submoas_queue = 1000  # 100
        self.max_hijack_queue = 10  # 10
        self.max_subhijack_queue = 1000  # 1
        self.hash_0 = hash_0
        self.mongo_client = create_mongo_client()
        self.mongo_db = get_mongo_db()
        self.log = get_logger()

        # 连接到redis
        # self.rj = rejson.Client(host='localhost', port=6379, decode_responses=True)
        # 连接到mongoDB

    def send_alarm_email(self, hijack_event, prefix, _event_type):
        victim_as = hijack_event['victim_as']
        hijack_as = hijack_event['hijack_as']
        start_datetime = hijack_event['start_datetime']
        now_ts = datetime.datetime.now().timestamp()
        if victim_as not in self.victim_alarm_dict:
            self.victim_alarm_dict[victim_as] = {'last_ts': -1}
        if int(now_ts) - int(self.victim_alarm_dict[victim_as]['last_ts']) > 24 * 60 * 60:
            col = self.mongo_client['bgp-user']['subscribed-as-email']
            doc = col.find_one({'_id': victim_as})
            if doc:
                template = f'''
<div>Hi, </div>
<br/>
<div>Hope this message finds you well. Greetings from the Institute for Network Sciences and Cyberspace at Tsinghua University. We have developed a BGP hijacking detection system (BGPWatch, https://bgpwatch.cgtf.net).</div>
<br/>
<div>Our system shows that prefix {prefix} is normally announced by your {victim_as}; however, at {start_datetime} (UTC), prefix {prefix} is also announced by {hijack_as}. Detailed information is available <a style="color:red" href="{'%srouteMonitorDetail2?detail_url=/events/%s|%s&type=%s' % (self.bgpwatch_url,hijack_event['event_id'].replace('/', '_'), _event_type,_event_type)}">here</a>.</div>
<br/>
<div>We would like to confirm with you whether this is a hijacking event or a false alarm of the system. Please click <a style="color:red" href="{'%srouteMonitorDetail2?detail_url=/events/%s|%s&tab=comments&type=%s' % (self.bgpwatch_url,hijack_event['event_id'].replace('/', '_'), _event_type,_event_type)}">here</a> to provide us with your feedback. Your time and response are greatly appreciated and will be very helpful for our research.</div>
<br/>
<div>Have a good day!</div>
<br/>
<div>Best regards,</div>
<div>Institute for Network Sciences and Cyberspace</div>
<div>Tsinghua University</div>
                '''
                for email in doc['email_list']:
                    send_email(email, template,
                               'Please Pay Attention - BGP Hijacking Alert',
                               'html')

                # set last send timestamp
                self.victim_alarm_dict[victim_as]['last_ts'] = now_ts

    def insert_ongoing_data(self, doc, _type):
        col = get_collection_by_name(_type, self.mongo_db)
        col.insert_one(doc)

    def addfield_ongoing_data(self, doc, update, _type):
        if len(doc['replay']) > 20:
            return
        
        prefix = doc['prefix']
        col = get_collection_by_name(_type, self.mongo_db)
        
        if _type == 'ongoing_subhijack':
            if len(doc['replay']) > 3:
                return
            doc['replay'][update.timestamp] = {
                k.replace('.', '_'): v
                for k, v in doc['replay'][update.timestamp].items()
            }
            update_pipelines = [{
                '$addFields': {
                    f'replay.{update.timestamp}':
                    doc['replay'][update.timestamp]
                }
            }, {
                '$addFields': {
                    'replay.1': {
                        '$objectToArray': f'$replay.{update.timestamp}'
                    }
                }
            }, {
                '$addFields': {
                    'replay.1': {
                        '$map': {
                            'input': "$replay.1",
                            'as': "item",
                            'in': {
                                'k': {
                                    '$replaceAll': {
                                        'input': "$$item.k",
                                        'find': "_",
                                        'replacement': "."
                                    }
                                },
                                'v': "$$item.v"
                            }
                        }
                    }
                }
            }, {
                '$addFields': {
                    f'replay.{update.timestamp}': {
                        '$arrayToObject': '$replay.1'
                    }
                }
            }, {
                '$unset': 'replay.1'
            }]
            col.update_one({'dict_k': doc['dict_k']}, update_pipelines)
        else:
            col.update_one({'prefix': prefix}, [{
                '$addFields': {
                    f'replay.{update.timestamp}': doc['replay'][update.timestamp]
                }
            }])

    def del_ongoing_data(self, doc, _type):
        col = get_collection_by_name(_type, self.mongo_db)
        if _type == 'ongoing_submoas' or _type == 'ongoing_subhijack':
            col.delete_one({'dict_k': doc['dict_k']})
            return
        prefix = doc['prefix']
        col.delete_one({'prefix': prefix})

    def over_turn_event_data(self, doc):
        old_doc = copy.copy(doc)
        if 'is_hijack' in doc:
            if 'hijack_as' in doc:
                self.over_turn_ongoing_data(doc, 'ongoing_hijack')
            else:
                self.over_turn_ongoing_data(doc, 'ongoing_moas')
        else:
            if 'hijack_as' in doc:
                self.over_turn_ongoing_data(doc, 'ongoing_subhijack')
            else:
                self.over_turn_ongoing_data(doc, 'ongoing_submoas')

        doc['over_turn'] = not doc['over_turn']
        if 'before_as' in doc:
            doc['suspicious_as'] = old_doc['before_as']
            doc['before_as'] = old_doc['suspicious_as']
            doc['before_as_country'] = old_doc['suspicious_as_country']
            doc['suspicious_as_country'] = old_doc['before_as_country']
            doc['before_as_description'] = old_doc['suspicious_as_description']
            doc['suspicious_as_description'] = old_doc['before_as_description']

        if 'sub_pfx_as' in doc:
            doc['sub_pfx_as'] = old_doc['super_pfx_as']
            doc['super_pfx_as'] = old_doc['sub_pfx_as']

        if 'is_hijack' in doc and 'hijack_as' in doc:
            doc['victim_as'] = old_doc['hijack_as']
            doc['hijack_as'] = old_doc['victim_as']
            doc['hijack_as_description'] = old_doc['victim_as_description']
            doc['victim_as_description'] = old_doc['hijack_as_description']
            doc['victim_as_country'] = old_doc['hijack_as_country']
            doc['hijack_as_country'] = old_doc['victim_as_country']

        elif 'is_subhijack' in doc and 'hijack_as' in doc:
            doc['victim_as'] = old_doc['hijack_as']
            doc['hijack_as'] = old_doc['victim_as']
            doc['hijack_as_description'] = old_doc['victim_as_description']
            doc['victim_as_description'] = old_doc['hijack_as_description']
            doc['victim_as_country'] = old_doc['hijack_as_country']
            doc['hijack_as_country'] = old_doc['victim_as_country']

    def over_turn_ongoing_data(self, doc, _type):
        col = get_collection_by_name(_type, self.mongo_db)
        if _type == 'ongoing_moas':
            col.update_one({'prefix': doc['prefix']}, {
                '$set': {
                    'over_turn': not doc['over_turn'],
                    'suspicious_as': doc['before_as'],
                    'before_as': doc['suspicious_as'],
                    'before_as_country': doc['suspicious_as_country'],
                    'suspicious_as_country': doc['before_as_country'],
                    'before_as_description': doc['suspicious_as_description'],
                    'suspicious_as_description': doc['before_as_description'],
                }
            })
        elif _type == 'ongoing_hijack':
            col.update_one({'prefix': doc['prefix']}, {
                '$set': {
                    'over_turn': not doc['over_turn'],
                    'suspicious_as': doc['before_as'],
                    'before_as': doc['suspicious_as'],
                    'before_as_country': doc['suspicious_as_country'],
                    'suspicious_as_country': doc['before_as_country'],
                    'before_as_description': doc['suspicious_as_description'],
                    'suspicious_as_description': doc['before_as_description'],
                    'victim_as': doc['hijack_as'],
                    'hijack_as': doc['victim_as'],
                    'hijack_as_description': doc['victim_as_description'],
                    'victim_as_description': doc['hijack_as_description'],
                    'victim_as_country': doc['hijack_as_country'],
                    'hijack_as_country': doc['victim_as_country']
                }
            })
        elif _type == 'ongoing_submoas':
            col.update_one(
                {
                    'prefix': doc['prefix'],
                    'subprefix': doc['subprefix']
                }, {
                    '$set': {
                        'over_turn': not doc['over_turn'],
                        'suspicious_as': doc['before_as'],
                        'before_as': doc['suspicious_as'],
                        'before_as_country': doc['suspicious_as_country'],
                        'suspicious_as_country': doc['before_as_country'],
                        'before_as_description':
                        doc['suspicious_as_description'],
                        'suspicious_as_description':
                        doc['before_as_description'],
                        'sub_pfx_as': doc['super_pfx_as'],
                        'super_pfx_as': doc['sub_pfx_as']
                    }
                })
        elif _type == 'ongoing_subhijack':
            col.update_one(
                {
                    'prefix': doc['prefix'],
                    'subprefix': doc['subprefix']
                }, {
                    '$set': {
                        'over_turn': not doc['over_turn'],
                        'suspicious_as': doc['before_as'],
                        'before_as': doc['suspicious_as'],
                        'before_as_country': doc['suspicious_as_country'],
                        'suspicious_as_country': doc['before_as_country'],
                        'before_as_description':
                        doc['suspicious_as_description'],
                        'suspicious_as_description':
                        doc['before_as_description'],
                        'sub_pfx_as': doc['super_pfx_as'],
                        'super_pfx_as': doc['sub_pfx_as'],
                        'victim_as': doc['hijack_as'],
                        'hijack_as': doc['victim_as'],
                        'hijack_as_description': doc['victim_as_description'],
                        'victim_as_description': doc['hijack_as_description'],
                        'victim_as_country': doc['hijack_as_country'],
                        'hijack_as_country': doc['victim_as_country']
                    }
                })

    def get_domain_by_prefix(self, prefix) -> List:
        ip, pfx = prefix.split('/')
        binary_str = ip_to_binary(ipaddress.ip_address(ip).exploded)
        domain_col = get_today_collection('DOMAIN')
        aggregate_pipelines = [
            {
                '$match': {
                    'binary_ip': {
                        '$regex': f'^{binary_str[:int(pfx)]}'
                    }
                }
            },
            {
                '$group': {
                    '_id': '$domain'
                }
            },
            {
                '$group': {
                    '_id': 'DOMAIN',
                    'list': {
                        '$push': '$_id'
                    }
                }
            },
        ]
        result = domain_col.aggregate(aggregate_pipelines)
        data = []
        try:
            data = result.next()['list']
        except Exception as e:
            data = []
        return data

    def new_moas_event(self, info_before, info_after, update):
        '''
        新增moas事件
        '''
        if update.type != 'A':
            return

        over_turn = False

        as_set = info_after['as_set']
        as_1, as_2 = tuple(info_after['as_set'])
        
        suspicious_as = update.as_path.split(' ')[-1]
        before_as = list(as_set - {update.as_path.split(' ')[-1]})[0]
        
        level, level_reason, hosts = self.hijack_level(update.prefix,as_set)
        is_hijack, reason,[will_overturn,hijack_valid,victim_valid] = HijackFilter.is_hijack(update.prefix,
                                                    as_2 if suspicious_as == as_1 else as_1,
                                                    suspicious_as,
                                                    info_before, info_after,
                                                    update.timestamp,update,'all', self.mongo_client,
                                                    self.mongo_db)

        if is_hijack and will_overturn:
            temp = suspicious_as
            suspicious_as = before_as
            before_as = temp
            over_turn = True

        self.running_moas_dict[update.prefix] = {
            "hash_0": self.hash_0,
            'over_turn': over_turn,
            'hijack_valid':hijack_valid,
            'victim_valid':victim_valid,
            "event_id": f'{update.prefix}-moas{update.timestamp}',
            "prefix": update.prefix,
            "start_timestamp": float(update.timestamp),
            "start_datetime": timestamp2date(float(update.timestamp)),
            "moas_set": list(info_after['as_set']),
            "suspicious_as": suspicious_as,
            "before_as": before_as,
            "before_as_country": get_as_country(before_as),
            "before_as_description": get_as_description(before_as,self.mongo_client),
            "suspicious_as_country": get_as_country(suspicious_as),
            "suspicious_as_description": get_as_description(suspicious_as,self.mongo_client),
            "is_hijack": is_hijack,
            "reason": reason,
            "level": level,
            "level_reason": level_reason,
            "websites_in_prefix": hosts,
        }

        #如果是劫持事件
        if self.running_moas_dict[update.prefix]['is_hijack']:
            def new_hijack_event():

                new_hijack_event = copy.deepcopy(self.running_moas_dict[update.prefix])
                
                new_hijack_event['event_id'] = f'{update.prefix}-hijack{update.timestamp}'
                new_hijack_event['victim_as'] = before_as
                new_hijack_event['hijack_as'] = suspicious_as
                new_hijack_event['victim_as_description'] = new_hijack_event['before_as_description']
                new_hijack_event['hijack_as_description'] = new_hijack_event['suspicious_as_description']
                new_hijack_event['victim_as_country'] = new_hijack_event['before_as_country']
                new_hijack_event['hijack_as_country'] = new_hijack_event['suspicious_as_country']

                self.running_hijack_dict[update.prefix] = new_hijack_event

                self.running_hijack_dict[update.prefix].update({
                    "replay": {
                        '-1': {
                            "stat": self.__count_oas(list(info_before['path_dict'].values())),
                            "path_list": list(info_before['path_dict'].values()),
                        }
                    },
                })
                # 把update存到replay中
                self.__update_hijack_replay(info_after, update)

            new_hijack_event()

            if len(hosts) != 0:
                domain = hosts[0]
                response = requests.post(self.lg_url,
                                         data=json.dumps({"target": domain}))
                # self.log.debug(f'Post {self.lg_url} {domain}')
                if response.status_code == 200:
                    data = response.json()
                    # self.log.debug(data)
                else:
                    self.log.error(response.json())
                    data = {'result': 'unknown'}
                self.log.debug(response.json())
                if 'result' in data:
                    self.running_hijack_dict[update.prefix]['lg_result'] = data['result']

            self.insert_ongoing_data(self.running_hijack_dict[update.prefix],'ongoing_hijack')
            self.send_alarm_email(self.running_hijack_dict[update.prefix],update.prefix, 'Ongoing Possible Hijack')
        self.insert_ongoing_data(self.running_moas_dict[update.prefix],'ongoing_moas')

    def new_submoas_event(self, pfx, super_pfx, pfx_before, super_pfx_before, pfx_after, super_pfx_after, update):
        sub_pfx_as = list(pfx_before['as_set'])[0]
        super_pfx_as = list(super_pfx_before['as_set'])[0]

        dict_k = f'{pfx}_{super_pfx}'
        
        as_1 = tuple(pfx_after['as_set'])[0]
        as_2 = tuple(super_pfx_after['as_set'])[0]

        level, level_reason, hosts = self.subhijack_level(pfx, super_pfx, pfx_after, super_pfx_after)
        is_subhijack, reason = HijackFilter.is_subhijack(
            pfx,
            super_pfx,
            as_2 if sub_pfx_as == as_1 else as_1,
            sub_pfx_as, 
            pfx_after,
            super_pfx_after,
            update.timestamp,
            update,
            'all',
            self.mongo_client,
            self.mongo_db)

        self.running_submoas_dict[dict_k] = {
            "hash_0": self.hash_0,
            "dict_k": dict_k,
            "event_id": f'{pfx}-submoas{update.timestamp}',
            "subprefix": update.prefix,
            'prefix': super_pfx,
            "start_timestamp": float(update.timestamp),
            "start_datetime": timestamp2date(float(update.timestamp)),
            "moas_set": list(pfx_after['as_set']),
            "sub_pfx_as": sub_pfx_as,
            "suspicious_as": sub_pfx_as,
            "super_pfx_as": super_pfx_as,
            "before_as": super_pfx_as,
            "prefix_list": [super_pfx, update.prefix],
            "suspicious_as_country": get_as_country(sub_pfx_as),
            "suspicious_as_description": get_as_description(sub_pfx_as,self.mongo_client),
            "before_as_country": get_as_country(super_pfx_as),
            "before_as_description": get_as_description(super_pfx_as,self.mongo_client),
            "is_subhijack": is_subhijack,
            "reason": reason,
            "level": level,
            "level_reason": level_reason,
            "websites_in_prefix": hosts,
        }
        
        if self.running_submoas_dict[dict_k]['is_subhijack']:
            
            def new_subhijack_event():
                new_subhijack_event = copy.deepcopy(self.running_submoas_dict[dict_k])
                new_subhijack_event['event_id'] = f'{pfx}-sub{update.timestamp}'
                new_subhijack_event['victim_as'] = super_pfx_as
                new_subhijack_event['hijack_as'] = sub_pfx_as
                new_subhijack_event['victim_as_description'] = new_subhijack_event['before_as_description']
                new_subhijack_event['hijack_as_description'] = new_subhijack_event['suspicious_as_description']
                new_subhijack_event['victim_as_country'] = new_subhijack_event['before_as_country']
                new_subhijack_event['hijack_as_country'] = new_subhijack_event['suspicious_as_country']
                self.running_subhijack_dict[dict_k] = new_subhijack_event
                self.running_subhijack_dict[dict_k].update({
                    "replay": {
                        "-1": {
                            pfx: [],
                            super_pfx:
                            list(super_pfx_before['path_dict'].values()),
                        }
                    },
                })
                self.__update_subhijack_replay(pfx_after,super_pfx_after, update, dict_k)

            def verify_with_lg():
                # Only first
                domain = hosts[list(hosts.keys())[0]][0]
                response = requests.post(self.lg_url,data=json.dumps({"target": domain}))
                self.log.debug(f'Post {self.lg_url} {domain}')
                data = response.json() if response.status_code == 200 else {'result': 'unknown'}
                self.log.info(data)
                self.running_subhijack_dict[dict_k]['lg_result'] = data.get('result','unknown')

            new_subhijack_event()

            if len(hosts) != 0 and len(hosts[list(hosts.keys())[0]]) != 0:
                verify_with_lg()

            self.insert_ongoing_data(self.running_subhijack_dict[dict_k],'ongoing_subhijack')
            self.send_alarm_email(self.running_subhijack_dict[dict_k],update.prefix, 'Ongoing Possible SubHijack')

        self.submoas_dict.setdefault(pfx,[])
        self.submoas_dict[pfx].append(super_pfx)
        self.submoas_super_dict.setdefault(super_pfx,[])
        self.submoas_super_dict[super_pfx].append(pfx)

        self.insert_ongoing_data(self.running_submoas_dict[f'{pfx}_{super_pfx}'], 'ongoing_submoas')

    def update_moas_event(self, info_after, update):
        if update.prefix not in self.running_moas_dict:
            return
        if self.running_moas_dict[update.prefix]['is_hijack']:
            if update.prefix not in self.running_hijack_dict:
                self.running_moas_dict[update.prefix]['is_hijack'] = False
                self.del_ongoing_data(self.running_hijack_dict[update.prefix],'ongoing_hijack')
                return
            self.__update_hijack_replay(info_after, update)
            self.addfield_ongoing_data(self.running_hijack_dict[update.prefix],update, 'ongoing_hijack')

    def update_submoas_event(self, pfx, super_pfx, pfx_after, super_pfx_after, update):
        if update.prefix not in self.submoas_dict:
            return
        
        dict_k = f'{pfx}_{super_pfx}'
        
        if self.running_submoas_dict[f'{pfx}_{super_pfx}']['is_subhijack']:
            self.__update_subhijack_replay(pfx_after, super_pfx_after, update,dict_k)
            self.addfield_ongoing_data(self.running_subhijack_dict[f'{pfx}_{super_pfx}'], update, 'ongoing_subhijack')
        pass
    
    def verify_subhijack_in_roa(self, pfx, super_pfx):
        key = f'{pfx}_{super_pfx}'

        if not self.running_submoas_dict[key]['is_subhijack']:
            return 
        
        suspicious_as = self.running_submoas_dict[key]['suspicious_as']
        before_as = self.running_submoas_dict[key]['before_as']
        
        reason = self.running_submoas_dict[key]['reason']
        reason_list = reason.split('|')

        hiajck_not_in_roa_reason = get_reason(Reason.ROA_NOT_MATCH,suspicious_as,pfx)
        victim_in_roa_reason = get_reason(Reason.ROA_MATCH,before_as,super_pfx)
        hiajck_in_roa_reason = get_reason(Reason.ROA_MATCH,suspicious_as,pfx)
        victim_not_in_roa_reason = get_reason(Reason.ROA_NOT_MATCH,before_as,super_pfx)
        if hiajck_not_in_roa_reason in reason_list:
            reason_list.remove(hiajck_not_in_roa_reason)
        if victim_in_roa_reason in reason_list:
            reason_list.remove(victim_in_roa_reason)
        if hiajck_in_roa_reason in reason_list:
            reason_list.remove(hiajck_in_roa_reason)
        if victim_not_in_roa_reason in reason_list:
            reason_list.remove(victim_not_in_roa_reason)

        hiajck_in_roa = match_in_roa(
            pfx, suspicious_as,
            self.running_submoas_dict[key]['start_timestamp'],
            self.mongo_client)
        victim_in_roa = match_in_roa(
            super_pfx, before_as,
            self.running_submoas_dict[key]['start_timestamp'],
            self.mongo_client)
        
        if hiajck_in_roa and victim_in_roa:
            reason_list.append(hiajck_in_roa_reason)
            reason_list.append(victim_in_roa_reason)

            self.running_submoas_dict[key]['is_subhijack'] = False
            if key in self.running_subhijack_dict:
                self.del_ongoing_data(self.running_subhijack_dict[key], 'ongoing_subhijack')
                del self.running_subhijack_dict[key]

        elif hiajck_in_roa and not victim_in_roa:
            reason_list.append(hiajck_in_roa_reason)
            reason_list.append(victim_not_in_roa_reason)
            self.running_submoas_dict[key]['is_subhijack'] = False
            if key in self.running_subhijack_dict:
                self.del_ongoing_data(self.running_subhijack_dict[key], 'ongoing_subhijack')
                del self.running_subhijack_dict[key]

        elif not hiajck_in_roa and victim_in_roa:
            reason_list.append(hiajck_not_in_roa_reason)
            reason_list.append(victim_in_roa_reason)
            
        elif not hiajck_in_roa and not victim_in_roa:
            reason_list.append(hiajck_not_in_roa_reason)
            reason_list.append(victim_not_in_roa_reason)
                        
        self.running_submoas_dict[key]['reason'] = '|'.join(reason_list)
        if key in self.running_subhijack_dict:
            self.running_subhijack_dict[key]['reason'] = '|'.join(reason_list)

    def end_moas_event_manual(self, prefix, timestamp, reason):
        if prefix not in self.running_moas_dict:
            return
        event = self.running_moas_dict[prefix]
        event['after_as'] = '-'
        event['end_timestamp'] = float(timestamp)
        event['end_datetime'] = timestamp2date(float(timestamp))
        event['duration'] = sec2readable(event['end_timestamp'] - event['start_timestamp'])
        # 存入moas队列
        event['reason'] += f'|{reason}'
        is_hijack = self.running_moas_dict[prefix]['is_hijack']
        event['is_hijack'] = False
        
        self.finished_moas_queue.put(event)
        del self.running_moas_dict[prefix]
        self.del_ongoing_data(event, 'ongoing_moas')
        
        if is_hijack:
            if prefix in self.running_hijack_dict:
                del self.running_hijack_dict[prefix]
            self.del_ongoing_data(event, 'ongoing_hijack')

    def end_moas_event(self, info_after, update):
        if update.prefix not in self.running_moas_dict or 'as_set' not in info_after:
            return

        self.verify_roa(update.prefix)

        event = self.running_moas_dict[update.prefix]
        event['after_as'] = list(info_after['as_set'])[0]
        event['end_timestamp'] = float(update.timestamp)
        event['end_datetime'] = timestamp2date(float(update.timestamp))
        event['duration'] = sec2readable(event['end_timestamp'] - event['start_timestamp'])
        # 存入moas队列

        if event['end_timestamp'] - event['start_timestamp'] == 0:
            reason = get_reason(Reason.DURATION_0)
            self.running_moas_dict[update.prefix]['is_hijack'] = False
            if update.prefix in self.running_hijack_dict:
                del self.running_hijack_dict[update.prefix]
                self.del_ongoing_data(event, 'ongoing_hijack')
                self.running_moas_dict[update.prefix]['reason'] = reason

        self.finished_moas_queue.put(event)
        is_hijack = self.running_moas_dict[update.prefix]['is_hijack']
        del self.running_moas_dict[update.prefix]

        if is_hijack:

            def end_hijack_event():
                self.__update_hijack_replay(info_after, update)
                self.running_hijack_dict[update.prefix].update({
                    'after_as': list(info_after['as_set'])[0],
                    'end_timestamp': float(update.timestamp),
                    'end_datetime': timestamp2date(float(update.timestamp)),
                    'duration': sec2readable(event['end_timestamp'] - event['start_timestamp']),
                })
                # 存入moas_hijack队列
                self.finished_hijack_queue.put(self.running_hijack_dict[update.prefix])  # 这里增加的 finished_hijack_queue的数量
                del self.running_hijack_dict[update.prefix]

            if update.prefix in self.running_hijack_dict:
                end_hijack_event()
                self.del_ongoing_data(event, 'ongoing_hijack')
            else:
                self.log.error(f"{update.prefix} not in dict")

        self.del_ongoing_data(event, 'ongoing_moas')

    def verify_roa(self, prefix):
        
        if not self.running_moas_dict[prefix]['is_hijack']:
            return
        
        suspicious_as = self.running_moas_dict[prefix]['suspicious_as']
        before_as = self.running_moas_dict[prefix]['before_as']
        
        reason_list = self.running_moas_dict[prefix]['reason'].split('|')

        hiajck_not_in_roa_reason = get_reason(Reason.ROA_NOT_MATCH,suspicious_as,prefix)
        victim_in_roa_reason = get_reason(Reason.ROA_MATCH,before_as,prefix)
        hiajck_in_roa_reason = get_reason(Reason.ROA_MATCH,suspicious_as,prefix)
        victim_not_in_roa_reason = get_reason(Reason.ROA_NOT_MATCH,before_as,prefix)
        if hiajck_not_in_roa_reason in reason_list:
            reason_list.remove(hiajck_not_in_roa_reason)
        if victim_in_roa_reason in reason_list:
            reason_list.remove(victim_in_roa_reason)
        if hiajck_in_roa_reason in reason_list:
            reason_list.remove(hiajck_in_roa_reason)
        if victim_not_in_roa_reason in reason_list:
            reason_list.remove(victim_not_in_roa_reason)

        hiajck_in_roa = match_in_roa(
            prefix, suspicious_as,
            self.running_moas_dict[prefix]['start_timestamp'],
            self.mongo_client)
        victim_in_roa = match_in_roa(
            prefix, before_as,
            self.running_moas_dict[prefix]['start_timestamp'],
            self.mongo_client)
        

        if hiajck_in_roa and victim_in_roa:
            reason_list.append(hiajck_in_roa_reason)
            reason_list.append(victim_in_roa_reason)

            self.running_moas_dict[prefix]['is_hijack'] = False
            if prefix in self.running_hijack_dict:
                self.del_ongoing_data(self.running_hijack_dict[prefix],
                                      'ongoing_hijack')
                del self.running_hijack_dict[prefix]

        elif hiajck_in_roa and not victim_in_roa:
            self.log.debug(f'{prefix} need overturn in update')
            self.log.debug(f'{prefix}\n{reason_list}\n{hiajck_not_in_roa_reason}\n{victim_in_roa_reason}')
            reason_list.append(hiajck_in_roa_reason)
            reason_list.append(victim_not_in_roa_reason)
            

            if 'victim_valid' in self.running_moas_dict[prefix] and 'hijack_valid' in self.running_moas_dict[prefix]:
                self.running_moas_dict[prefix]['hijack_valid'] = True
                if self.running_moas_dict[prefix]['victim_valid'] and self.running_moas_dict[prefix]['hijack_valid']:
                    self.log.debug(f'[VERIFY ROA] set (OVERTURN) {prefix}')
                    self.running_moas_dict[prefix]['is_hijack'] = False
                    if prefix in self.running_hijack_dict:
                        self.del_ongoing_data(self.running_hijack_dict[prefix],
                                            'ongoing_hijack')
                        del self.running_hijack_dict[prefix]
                else:
                    self.running_moas_dict[prefix]['reason'] = '|'.join(reason_list)
                    self.over_turn_event_data(self.running_moas_dict[prefix])
                    if prefix in self.running_hijack_dict:
                        self.running_hijack_dict[prefix]['reason'] = '|'.join(reason_list)
                        self.over_turn_event_data(self.running_hijack_dict[prefix])
                pass

        elif not hiajck_in_roa and victim_in_roa:
            reason_list.append(hiajck_not_in_roa_reason)
            reason_list.append(victim_in_roa_reason)
            if 'victim_valid' in self.running_moas_dict[prefix] and 'hijack_valid' in self.running_moas_dict[prefix]:
                self.running_moas_dict[prefix]['victim_valid'] = True
                if self.running_moas_dict[prefix]['victim_valid'] and self.running_moas_dict[prefix]['hijack_valid']:
                    self.running_moas_dict[prefix]['is_hijack'] = False
                    if prefix in self.running_hijack_dict:
                        self.del_ongoing_data(self.running_hijack_dict[prefix],
                                            'ongoing_hijack')
                        del self.running_hijack_dict[prefix]

            
        elif not hiajck_in_roa and not victim_in_roa:
            reason_list.append(hiajck_not_in_roa_reason)
            reason_list.append(victim_not_in_roa_reason)
                        
        self.running_moas_dict[prefix]['reason'] = '|'.join(reason_list)
        if prefix in self.running_hijack_dict:
            self.running_hijack_dict[prefix]['reason'] = '|'.join(reason_list)

    def end_submoas_event_manual(self, pfx_key, timestamp, reason):
        try:
            pfx, super_pfx = pfx_key.split('_')
            if pfx not in self.submoas_dict:
                self.log.debug(f'{pfx} not in self.submoas_dict')
                return
            event = self.running_submoas_dict[pfx_key]
            event['end_timestamp'] = float(timestamp)
            event['end_datetime'] = timestamp2date(float(timestamp))
            event['duration'] = sec2readable(event['end_timestamp'] - event['start_timestamp'])
            event['reason'] += f'|{reason}'
            is_hijack = self.running_submoas_dict[pfx_key]['is_subhijack']

            event['is_subhijack'] = False
            self.finished_submoas_queue.put(event)
            del self.running_submoas_dict[f'{pfx}_{super_pfx}']
            self.submoas_dict[pfx].remove(super_pfx)
            self.submoas_super_dict[super_pfx].remove(pfx)
            if len(self.submoas_dict[pfx]) == 0:
                del self.submoas_dict[pfx]
            if len(self.submoas_super_dict[super_pfx]) == 0:
                del self.submoas_super_dict[super_pfx]

            self.del_ongoing_data(event, 'ongoing_submoas')

            if is_hijack and pfx_key in self.running_subhijack_dict:
                del self.running_subhijack_dict[pfx_key]
                self.del_ongoing_data(event, 'ongoing_subhijack')
        except Exception as e:
            exception_happen(e)

    def end_submoas_event(self, pfx, super_pfx, pfx_after, super_pfx_after,
                          update):
        if pfx not in self.submoas_dict:
            return

        self.verify_subhijack_in_roa(pfx, super_pfx)

        dict_k = f'{pfx}_{super_pfx}'
        
        event = self.running_submoas_dict[dict_k]
        event['end_timestamp'] = float(update.timestamp)
        event['end_datetime'] = timestamp2date(float(update.timestamp))
        event['duration'] = sec2readable(event['end_timestamp'] - event['start_timestamp'])
        if event['end_timestamp'] - event['start_timestamp'] == 0:
            reason = get_reason(Reason.DURATION_0)
            self.running_submoas_dict[dict_k]['is_subhijack'] = False
            if dict_k in self.running_subhijack_dict:
                del self.running_subhijack_dict[dict_k]
                self.del_ongoing_data(event, 'ongoing_subhijack')
                self.running_submoas_dict[dict_k]['reason'] = reason

        self.finished_submoas_queue.put(event)
        is_hijack = self.running_submoas_dict[dict_k]['is_subhijack']
        del self.running_submoas_dict[dict_k]

        if is_hijack:

            def end_subhijack_event():
                self.__update_subhijack_replay(pfx_after, super_pfx_after, update,dict_k)

                self.running_subhijack_dict[dict_k].update({
                    'end_timestamp': float(update.timestamp),
                    'end_datetime': timestamp2date(float(update.timestamp)),
                    'duration': sec2readable(event['end_timestamp'] - event['start_timestamp']),
                })
                self.finished_subhijack_queue.put(self.running_subhijack_dict[dict_k])
                del self.running_subhijack_dict[dict_k]

            if dict_k in self.running_subhijack_dict:
                end_subhijack_event()
                self.del_ongoing_data(event, 'ongoing_subhijack')
            else:
                self.log.error(f"{dict_k} not in dict")

        self.submoas_dict[pfx].remove(super_pfx)
        self.submoas_super_dict[super_pfx].remove(pfx)

        self.submoas_dict.pop(pfx, None) if not self.submoas_dict[pfx] else None
        self.submoas_super_dict.pop(super_pfx, None) if not self.submoas_super_dict[super_pfx] else None

        self.del_ongoing_data(event, 'ongoing_submoas')

    def write_event_to_file(self):
        self.log.debug('[SAVE DATA] start write data to db')
        
        def do_aggregate(queue,aggregate_func,col_name):
            finished_num = queue.qsize()
            e_i_list = []
            for _ in range(finished_num):
                e_i = queue.get()
                e_i_list.append(e_i)
            aggregate_func(e_i_list, get_collection_by_name( col_name, self.mongo_db))  # 写入mongoDB的一个表中
        
            pass
        
        do_aggregate(self.finished_moas_queue,aggregate_moas_events,'moas')
        do_aggregate(self.finished_submoas_queue,aggregate_submoas_events,'sub-moas')
        do_aggregate(self.finished_hijack_queue,aggregate_hijack_events,'possible-hijack')
        do_aggregate(self.finished_subhijack_queue,aggregate_subhijack_events,'sub-possible-hijack')       

    def logging(self, timestamp, update_counter, rib_prefixes):
        # os.system("clear")
        print(
            f'''
current time:\t\t\t\t{timestamp2date(timestamp)}
hash_0:\t\t\t\t\t{self.hash_0}
pid:\t\t\t\t\t{os.getpid()}
processed update num:\t\t\t{update_counter}
rib prefixes num:\t\t\t{rib_prefixes}
current running hijack num:\t\t{len(self.running_hijack_dict)}
current running subhijack num:\t\t{len(self.running_subhijack_dict)}
current running moas num:\t\t{len(self.running_moas_dict)}
current running submoas num:\t\t{len(self.running_submoas_dict)}
finished hijack num:\t\t\t{self.finished_hijack_queue.qsize()}
finished subhijack num:\t\t\t{self.finished_subhijack_queue.qsize()}
finished moas num:\t\t\t{self.finished_moas_queue.qsize()}
finished submoas num:\t\t\t{self.finished_submoas_queue.qsize()}

        ''',
            # finished moas num:\t\t\t{self.finished_moas_queue.qsize()}
            # current running submoas num:\t\t{len(self.running_submoas_dict)}
            # current running moas num:\t\t{len(self.running_moas_dict)}
            # finished submoas num:\t\t\t{self.finished_submoas_queue.qsize()}
            end='\r',
            flush=True)

    def __count_oas(self, path_list):
        stat = defaultdict(int)
        for path in path_list:
            stat[path.split(' ')[-1]] += 1
        return stat

    def __update_hijack_replay(self, info_after, update):
        self.running_hijack_dict[update.prefix].setdefault('replay',{})
        timestamp = update.timestamp
        
        i = 1
        while timestamp in self.running_hijack_dict[update.prefix]['replay']:
            timestamp = f'{timestamp.split("-")[0]}-{i}'
            i += 1

        self.running_hijack_dict[update.prefix]['replay'].update({
            timestamp: {
                "stat": self.__count_oas(list(info_after['path_dict'].values())),
                "path_list": list(info_after['path_dict'].values()),
                "community": update.community if hasattr(update, 'community') else ""
            }
        })

    def __update_subhijack_replay(self, pfx_after, super_pfx_after, update, dict_k):
        if super_pfx_after == None:
            return

        self.running_subhijack_dict[dict_k].setdefault('replay',{})
        timestamp = update.timestamp
        
        i = 1
        while timestamp in self.running_subhijack_dict[dict_k]['replay']:
            timestamp = f'{timestamp}-{i}'
            i += 1

        self.running_subhijack_dict[dict_k]['replay'].update({
            timestamp: {
                'pfx': [] if not pfx_after else list(pfx_after['path_dict'].values()),
                'super_pfx': list(super_pfx_after['path_dict'].values()),
            }
        })

    def hijack_level(self, prefix, moas_set):
        '''
        生成劫持事件等级

        返回 事件等级，描述，IP/域名列表
        '''
        
        hosts = self.get_domain_by_prefix(prefix)
        
        num = len(hosts)
        descr_info1 = f"{num} websites in the prefix." if num > 0 else ''
        
        if num > 5:
            level = 'high'
        elif num > 0:
            level = 'middle'
        else:
            level = 'low'
        
        for asn in moas_set:
            # 如果是聚合AS
            if '[' in asn or '{' in asn or '}' in asn:
                return '', '', hosts
            
            if asn and str(asn) in knowledge_base.important_as_dict:
                descr_info2 = f"{asn} is Cloud|IDC|CDN or top content provider."
                level =  'middle' if level == 'low' else level
                break
            else:
                descr_info2 = ''
        
        return level, descr_info1 + descr_info2, hosts

    def subhijack_level(self, prefix, super_pfx, pfx_after, super_pfx_after):
        moas_set = pfx_after['as_set'] & super_pfx_after['as_set']
        level = 'low'
        descr_info1 = ''

        hosts = {
            f'{prefix}': self.get_domain_by_prefix(prefix),
            f'{super_pfx}': self.get_domain_by_prefix(super_pfx)
        }
        num = len([item for sublist in list(hosts.values()) for item in sublist])

        if num > 5:
            descr_info1 += str(num) + " websites in the prefix."
            level = 'high'
        elif num > 0:
            descr_info1 += str(num) + " websites in the prefix."
            level = 'middle'

        descr_info2 = ''
        for asn in moas_set:
            if '[' in asn or '{' in asn or '}' in asn:
                return '', '', hosts
            if str(asn) in knowledge_base.important_as_dict:
                descr_info2 = asn + " is Cloud|IDC|CDN or top content provider."
                if level == 'low':
                    level = 'middle'
                    break
            else:
                descr_info2 = ''

        return level, descr_info1 + descr_info2, hosts


