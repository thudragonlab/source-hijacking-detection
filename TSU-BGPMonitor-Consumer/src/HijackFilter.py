from typing import Tuple
from utils.get_collections import get_whois_collection
from utils.get_as_description import get_as_description
from utils.roa_util import match_in_roa
from src.KnowledgeBase import knowledge_base
from utils.reason_util import Reason,get_reason
from multiprocessing.pool import ThreadPool
from utils.mongo_util import get_collection_by_name, get_daily_collection
from utils.common_util import exception_happen, generate_supernet_regex
from utils.legal_moas_util import get_legal_moas, update_legal_moas
from utils.log_util import get_logger
"""filter legitimate moas event"""

verified_legal_moas = get_legal_moas()


def is_too_freqency(as1, as2,  timestamp, mongo_db, col_name):
    try:
        log = get_logger()
        start_timestamp = int(timestamp) - 24 * 60 * 60 * 7
        end_timestamp = int(timestamp)
        find_condition = {
            'victim_as': as1,
            'hijack_as': as2,
            'start_timestamp': {
                '$gt': start_timestamp,
                '$lt': end_timestamp
            }
        }
        hijack_count = get_collection_by_name(
            col_name, mongo_db).count_documents(find_condition)
        if hijack_count != 0:
            log.debug(
                f'HIJACK COUNT {hijack_count} moas_set => [{as1} {as2}] condition => {find_condition}'
            )
        if hijack_count >= 5:
            reason = get_reason(Reason.IS_TOO_FREQENCY)
            # TODO delete found data
            delete_result = get_collection_by_name(
                col_name, mongo_db).delete_many(find_condition)
            log.debug(
                f'Delete {delete_result.deleted_count} data moas_set => [{as1} {as2}] cause frequently'
            )
            return False, reason
    except Exception as e:
        exception_happen(e)
    return True, ''

def is_not_import_or_export(as1, as2, prefix,timestamp,mongo_client):
    col = get_whois_collection(timestamp,mongo_client)
    as1_str = f'AS{as1}'
    as2_str = f'AS{as2}'
    as1_items = col.find({'aut-num':{'$in':[int(as1),as1_str]}},{'export':1,'import':1})
    
    for as1_item in as1_items:
        if 'export' in as1_item:
            export_str = ''.join(as1_item['export'])
            if as2 in export_str:
                reason = get_reason(Reason.AS1_EXPORT_AS2,as1,as2)
                return False, reason
        if 'import' in as1_item:
            import_str = ''.join(as1_item['import'])
            if as2 in import_str:
                reason = get_reason(Reason.AS1_IMPORT_AS2,as1,as2)
                return False, reason
        
    as2_items = col.find({'aut-num':{'$in':[int(as2),as2_str]}},{'export':1,'import':1})

    for as2_item in as2_items:
        if 'export' in as2_item:
            export_str = ''.join(as2_item['export'])
            if as1 in export_str:
                reason = get_reason(Reason.AS2_EXPORT_AS1,as2,as1)
                return False, reason
        if 'import' in as2_item:
            import_str = ''.join(as2_item['import'])
            if as1 in import_str:
                reason = get_reason(Reason.AS2_IMPORT_AS1,as2,as1)
                return False, reason

    return True, ''

def is_not_in_as_rel_dict(as1, as2, prefix):
    #判断一个是不是就行了？？

    # 这里的peer和下面的V4 V6 peer有什么区别？
    if knowledge_base.as_rel_dict.get(as1) != None:
        if knowledge_base.as_rel_dict[as1].get('peers') != None:
            peers = set(knowledge_base.as_rel_dict[as1]['peers'])
            providers = set(knowledge_base.as_rel_dict[as1]['provider'])
            customers = set(knowledge_base.as_rel_dict[as1]['customer'])
            if as2 in peers:
                reason =  get_reason(Reason.PEER)
                return False, reason
            if as2 in providers:
                reason =  get_reason(Reason.P2C,as2,as1)
                return False, reason
            if as2 in customers:
                reason =  get_reason(Reason.P2C,as1,as2)
                return False, reason
    #  as2 是as1的peer
    if knowledge_base.as_rel_dict.get(as2) != None:
        if knowledge_base.as_rel_dict[as2].get('peers') != None:
            peers = set(knowledge_base.as_rel_dict[as2]['peers'])
            if as1 in peers:
                reason =  get_reason(Reason.PEER)
                return False, reason
            if as1 in providers:
                reason =  get_reason(Reason.P2C,as1,as2)
                return False, reason
            if as1 in customers:
                reason =  get_reason(Reason.P2C,as2,as1)
                return False, reason
    return True, ''

def not_irr_route_filter(as_1, as_2, prefix,timestamp, mongo_client):
    '''
    用prefix查询route里面的origin是不是as2，是就返回False,'irr route object matched' 否则 Ture,''
    '''
    
    col = get_whois_collection(timestamp,mongo_client)
    route_col_name = "route6" if ":" in prefix else "route"
    hijack_find_condition = {
            f'{route_col_name}': {
                '$in': generate_supernet_regex(prefix)
            },
            'origin': {'$in':[f'AS{as_2}',f'as{as_2}']}
        }
    victim_find_condition = {
            f'{route_col_name}': {
                '$in': generate_supernet_regex(prefix)
            },
            'origin': {'$in':[f'AS{as_1}',f'as{as_1}']}
        }
    
    item_h = col.find_one(hijack_find_condition)
    item_v = col.find_one(victim_find_condition)

    hijack_vaild = False
    victim_valid = False

    if item_h and item_v:
        reason = f"{get_reason(Reason.WHOIS_MATCH,as_1,item_h[route_col_name])}|{get_reason(Reason.WHOIS_MATCH,as_2,item_v[route_col_name])}"
        hijack_vaild = True
        victim_valid = True
        return False, reason,hijack_vaild,victim_valid
    elif item_v:
        victim_valid = True
        return True, f"{get_reason(Reason.WHOIS_NOT_MATCH,as_2,prefix)}|{get_reason(Reason.WHOIS_MATCH,as_1,item_v[route_col_name])}",hijack_vaild,victim_valid
    elif item_h:
        hijack_vaild = True
        return True, f"{get_reason(Reason.WHOIS_NOT_MATCH,as_1,prefix)}|{get_reason(Reason.WHOIS_MATCH,as_2,item_h[route_col_name])}",hijack_vaild,victim_valid
    else:
        reason = f"{get_reason(Reason.WHOIS_NOT_MATCH,as_2,prefix)}|{get_reason(Reason.WHOIS_NOT_MATCH,as_1,prefix)}"
        return True, reason,hijack_vaild,victim_valid

def not_irr_route_filter_subhijack(as1, as2, subprefix,super_prefix,timestamp, mongo_client):
    '''
    用prefix查询route里面的origin是不是as2，是就返回False,'irr route object matched' 否则 Ture,''
    '''

    col = get_whois_collection(timestamp,mongo_client)
    route_col_name = "route6" if ":" in subprefix else "route"
    
    hijack_find_condition = {
            f'{route_col_name}': {
                '$in': generate_supernet_regex(subprefix)
            },
            'origin': {'$in':[f'AS{as2}',f'as{as2}']}
        }
    victim_find_condition = {
            f'{route_col_name}': {
                '$in': generate_supernet_regex(super_prefix)
            },
            'origin': {'$in':[f'AS{as1}',f'as{as1}']}
        }
    
    item_h = col.find_one(hijack_find_condition)
    item_v = col.find_one(victim_find_condition)
    
    if not item_h and not item_v:
        return True, f"{get_reason(Reason.WHOIS_NOT_MATCH,as2,subprefix)}|{get_reason(Reason.WHOIS_NOT_MATCH,as1,super_prefix)}"
    elif not item_v:
        return False, f"{get_reason(Reason.WHOIS_MATCH,as2,item_h[route_col_name])}|{get_reason(Reason.WHOIS_NOT_MATCH,as1,super_prefix)}"
    elif not item_h:
        return True, f"{get_reason(Reason.WHOIS_NOT_MATCH,as2,subprefix)}|{get_reason(Reason.WHOIS_MATCH,as1,item_v[route_col_name])}"
    else:
        return False, f"{get_reason(Reason.WHOIS_MATCH,as2,item_h[route_col_name])}|{get_reason(Reason.WHOIS_MATCH,as1,item_v[route_col_name])}"

def not_same_admin_filter(as1, as2, timestamp, mongo_client):
    '''
    找as1和as2的 admin-c tech-c mnt-lower 任意一个一样就是False 'Same orginization' ，否则 Ture

    prefix去掉/24 去查询inetnum/inet6num
    '''
    col = get_whois_collection(timestamp,mongo_client)
    if '{' in as1 or '{' in as2:
        return False, get_reason(Reason.PASS_AGGREGATE_ASN)
    as1_str = f'AS{as1}'
    as2_str = f'AS{as2}'
    items_as1 = col.find(
        {'aut-num':{'$in':[int(as1),as1_str]}}
        , {
            'admin-c': 1,
            'tech-c': 1,
            'mnt-lower': 1
        })
    for item_as1 in items_as1:
        if 'admin-c' in item_as1:
            item_as2 = col.find_one({'aut-num':{'$in':[int(as2),as2_str]},'admin-c':item_as1['admin-c']})
            if item_as2:
                reason = get_reason(Reason.WHOIS_SAME_ADMIN,as1,as2)
                return False, reason
            
        elif 'tech-c' in item_as1:
            item_as2 = col.find_one({'aut-num':{'$in':[int(as2),as2_str]},'tech-c':item_as1['tech-c']})
            if item_as2:
                reason = get_reason(Reason.WHOIS_SAME_TECH,as1,as2)
                return False, reason
            
        elif 'mnt-lower' in item_as1:
            item_as2 = col.find_one({'aut-num':{'$in':[int(as2),as2_str]},'mnt-lower':item_as1['mnt-lower']})
            if item_as2:
                reason = get_reason(Reason.WHOIS_SAME_MNT_LOWER,as1,as2)
                return False, reason
    
    return True, ''

def not_same_org_filter(as1, as2, prefix, mongo_client):
    '''
    找as1和as2的 admin-c tech-c mnt-lower 任意一个一样就是False 'Same orginization' ，否则 Ture

    prefix去掉/24 去查询inetnum/inet6num
    '''
    
    col = get_daily_collection('as_info', mongo_client)
    if '{' in as1 or '{' in as2:
        return False, get_reason(Reason.PASS_AGGREGATE_ASN)
    as1_str = f'AS{as1}'
    as2_str = f'AS{as2}'
    item_as1 = col.find_one(
        {'_id':str(as1)}, {
            'organization.orgId': 1,
        })
    item_as2 = col.find_one(
        {'_id':str(as2)}, {
            'organization.orgId': 1,
        })
    if item_as1 and item_as2:
        reason = get_reason(Reason.AS_INFO_SAME_ORG_ID,as1,as2)
        if 'organization' in item_as1 and 'orgId' in item_as1['organization'] and 'organization' in item_as2 and 'orgId' in item_as2['organization']:
            if item_as1['organization']['orgId'] == item_as2['organization']['orgId']:
                
                return False, reason
       
    return True, ''

def not_same_org_filter_between_as_prefix(as1, as2, prefix,timestamp,mongo_client):
    '''
    找as1和as2的 admin-c tech-c mnt-lower 任意一个一样就是False 'Same orginization' ，否则 Ture

    prefix去掉/24 去查询inetnum/inet6num
    '''
    
    col = get_whois_collection(timestamp,mongo_client)
    prefix_ip = prefix.split('/')[0]

    item_as1 = col.find_one({'aut-num': f'AS{as2}'}, {
        'admin-c': 1,
        'tech-c': 1,
        'mnt-lower': 1
    })
    if ':' in prefix:
        item_as2 = col.find_one({'inet6num': {
            '$regex': prefix_ip
        }}, {
            'admin-c': 1,
            'tech-c': 1,
            'mnt-lower': 1
        })
    else:
        item_as2 = col.find_one({'inetnum': {
            '$regex': prefix_ip
        }}, {
            'admin-c': 1,
            'tech-c': 1,
            'mnt-lower': 1
        })

    if not item_as1 or not item_as2:
        return True, ''

    if 'admin-c' in item_as1 and 'admin-c' in item_as2:
        if item_as1['admin-c'] == item_as2['admin-c']:
            reason = get_reason(Reason.WHOIS_SAME_ADMIN,as2,prefix)
            return False, reason

    if 'tech-c' in item_as1 and 'tech-c' in item_as2:
        if item_as1['tech-c'] == item_as2['tech-c']:
            reason = get_reason(Reason.WHOIS_SAME_TECH,as2,prefix)
            return False, reason

    if 'mnt-lower' in item_as1 and 'mnt-lower' in item_as2:
        if item_as1['mnt-lower'] == item_as2['mnt-lower']:
            reason = get_reason(Reason.WHOIS_SAME_MNT_LOWER,as2,prefix)
            return False, reason

    return True, ''

def is_incorrect_path(update, info_before, info_after):
    # try:
    # ...-V-H
    # ....V
    as_path = update.as_path
    vp = as_path.split(' ')[0]
    key = f'{vp}|{update.peer_address}'
    hijacker = info_after['path_dict'][key].split(' ')[-1]
    
    if 'path_dict' in info_before and key in info_after['path_dict'] :
        for path in info_before['path_dict'].values():
            path = path.split(' ') 
            hijack_path = info_after['path_dict'][key].split(' ')

            victim = path[-1]
            if victim in hijack_path:
                reason = get_reason(Reason.VH,as_path)

                return False, reason
        # ...-H
        # ...-H-V

            if hijacker in path:
                reason = get_reason(Reason.HV,path)

                return False, reason

        # ...X-H
        #    |
        #    V
        #如果倒数第二个as一样
            if len(path) > 1 and len(
                    hijack_path) > 1 and path[-2] == hijack_path[-2]:
                reason = get_reason(Reason.XH,as_path,path)

                return False, reason

            # except:
            #     pass
    return True, ''

def is_not_private_as(as1, as2, mongo_client):
    for asn in [as1, as2]:
        # 如果是聚合的
        if asn == '' or '{' in asn or '[' in asn or '}' in asn or '!' in asn:
            return False, get_reason(Reason.PASS_AGGREGATE_ASN)

        asn_num = int(asn)
        # 如果AS是私有AS
        if asn_num in range(64511, 65536):
            reason = get_reason(Reason.PRIVATE_AS,asn_num) 
            return False, reason

            #判断是否是ddos的AS
        asn_name = get_as_description(asn,mongo_client)
        if 'DDOS' in asn_name or 'ddos' in asn_name:
            reason = get_reason(Reason.DDOS_PROVIDER,asn)
            return False, reason

    return True, ''

def is_hijack(prefix, as1,as2, info_before, info_after, timestamp,update,filter_list, mongo_client,
              mongo_db) -> Tuple[bool, str]:
    '''
    判断是否是hijack事件
    moas_set中只有两个as的时候才可能是hijack
    Return bool reason
    '''
    
    reason = 'possible hijack'
    final_result = True
    will_overturn = False
    hijack_valid = False
    victim_valid = False
    if f'{as1} {as2} {prefix}' in verified_legal_moas:
        return False, verified_legal_moas[f'{as1} {as2} {prefix}'],[will_overturn,hijack_valid,victim_valid]
    if f'{as2} {as1} {prefix}' in verified_legal_moas:
        return False, verified_legal_moas[f'{as2} {as1} {prefix}'],[will_overturn,hijack_valid,victim_valid]
    

    as2_in_roa = match_in_roa(prefix,as2,timestamp,mongo_client)
    as1_in_roa = match_in_roa(prefix,as1,timestamp,mongo_client)

    if as2_in_roa and as1_in_roa:
        return False, f"{get_reason(Reason.ROA_MATCH,as2,prefix)}|{get_reason(Reason.ROA_MATCH,as1,prefix)}",[will_overturn,hijack_valid,victim_valid]
    elif as2_in_roa:
        _reason = f"{get_reason(Reason.ROA_MATCH,as2,prefix)}|{get_reason(Reason.ROA_NOT_MATCH,as1,prefix)}"
        will_overturn = True
        hijack_valid = True
    elif as1_in_roa:
        _reason = f"{get_reason(Reason.ROA_MATCH,as1,prefix)}|{get_reason(Reason.ROA_NOT_MATCH,as2,prefix)}"
        victim_valid = True
    else:
        _reason = f"{get_reason(Reason.ROA_NOT_MATCH,as2,prefix)}|{get_reason(Reason.ROA_NOT_MATCH,as1,prefix)}"
    reason  = _reason
    

    as_2 = as2
    as_1 = as1

    final_result,_reason,hv,vv = not_irr_route_filter(as_1, as_2, prefix,timestamp,mongo_client)
    if  not final_result:
        reason = f'{reason}|{_reason}'
        return final_result,reason,[will_overturn,hijack_valid,victim_valid]
    reason  = f'{reason}|{_reason}'
    if hv:
        hijack_valid = True
        will_overturn = True
    elif vv:
        victim_valid = True

    if hijack_valid and victim_valid:
        return False,reason,[will_overturn,hijack_valid,victim_valid]

    if will_overturn:
        as_2 = as1
        as_1 = as2
    
    
    
    tp = ThreadPool(processes=10)

    def solve_result(result):
        nonlocal final_result
        nonlocal reason
        if final_result and result[0] == False:
            final_result = result[0]
            reason =  f'{reason}|{result[1]}'

    # 出现频次过滤
    if filter_list == 'all' or filter_list['is_too_freqency']:
        tp.apply_async(is_too_freqency,
                    (as_1, as_2, timestamp, mongo_db, 'possible-hijack'),
                    callback=solve_result,
                    error_callback=exception_happen)
    # import export 过滤
    if filter_list == 'all' or filter_list['is_not_import_or_export']:
        tp.apply_async(is_not_import_or_export, (as_1, as_2, prefix,timestamp,mongo_client),
                    callback=solve_result,
                    error_callback=exception_happen)

    #商业关系过滤,来自CAIDA AS RANK
    if filter_list == 'all' or filter_list['is_not_in_as_rel_dict']:
        tp.apply_async(is_not_in_as_rel_dict, (as_1, as_2, prefix),
                    callback=solve_result,
                    error_callback=exception_happen)

    # 同国家AS过滤

    if filter_list == 'all' or filter_list['not_same_admin_filter']:
        tp.apply_async(not_same_admin_filter, (as_1, as_2, timestamp, mongo_client),
                        callback=solve_result,
                        error_callback=exception_happen)
    
    if filter_list == 'all' or filter_list['not_same_org_filter']:
        tp.apply_async(not_same_org_filter, (as_1, as_2, prefix, mongo_client),
                    callback=solve_result,
                    error_callback=exception_happen)


    #如果AS1和AS2是相同国家，就不算劫持

    if filter_list == 'all' or filter_list['not_same_org_filter_between_as_prefix']:
        tp.apply_async(not_same_org_filter_between_as_prefix,
                    (as_1, as_2, prefix,timestamp, mongo_client),
                    callback=solve_result,
                    error_callback=exception_happen)

    # 路径过滤:在as_path中处于前后位置
    if filter_list == 'all' or filter_list['is_incorrect_path']:
        tp.apply_async(is_incorrect_path,
                    (update, info_before, info_after),
                    callback=solve_result,
                    error_callback=exception_happen)

    # ？？？如果这个Dict里面有这两个as，就返回false，Reason不是很懂
    if filter_list == 'all' or filter_list['is_not_private_as']:
        tp.apply_async(is_not_private_as, (as_1, as_2, mongo_client),
                    callback=solve_result)
    tp.close()
    tp.join()

    return final_result, reason,[will_overturn,hijack_valid,victim_valid]

def is_subhijack(pfx, super_pfx, as1,as2,pfx_after, super_pfx_after, timestamp,update,filter_list,
                 mongo_client, mongo_db):

    if f'{as1} {as2} {pfx}_{super_pfx}' in verified_legal_moas:
        return False, verified_legal_moas[f'{as1} {as2} {pfx}_{super_pfx}']
    if f'{as2} {as1} {pfx}_{super_pfx}' in verified_legal_moas:
        return False, verified_legal_moas[f'{as2} {as1} {pfx}_{super_pfx}']
    if f'{as1} {as2} {pfx} {super_pfx}' in verified_legal_moas:
        return False, verified_legal_moas[f'{as1} {as2} {pfx} {super_pfx}']
    if f'{as2} {as1} {pfx} {super_pfx}' in verified_legal_moas:
        return False, verified_legal_moas[f'{as2} {as1} {pfx} {super_pfx}']
    if f'{as2} {as1} {pfx}' in verified_legal_moas:
        return False, verified_legal_moas[f'{as2} {as1} {pfx}']
    if f'{as1} {as2} {pfx}' in verified_legal_moas:
        return False, verified_legal_moas[f'{as1} {as2} {pfx}']
    if f'{as2} {as1} {super_pfx}' in verified_legal_moas:
        return False, verified_legal_moas[f'{as2} {as1} {super_pfx}']
    if f'{as1} {as2} {super_pfx}' in verified_legal_moas:
        return False, verified_legal_moas[f'{as1} {as2} {super_pfx}']
    
    
    reason = 'possible subhijack'
    final_result = True

    as2_in_roa = match_in_roa(pfx,as2,timestamp,mongo_client)
    as1_in_roa = match_in_roa(super_pfx,as1,timestamp,mongo_client)

    if as2_in_roa and as1_in_roa:
        return False, f"{get_reason(Reason.ROA_MATCH,as1,super_pfx)}|{get_reason(Reason.ROA_MATCH,as2,pfx)}"
    elif as2_in_roa:
        return False,f"{get_reason(Reason.ROA_NOT_MATCH,as1,super_pfx)}|{get_reason(Reason.ROA_MATCH,as2,pfx)}"
    
    elif as1_in_roa:
        _reason = f"{get_reason(Reason.ROA_NOT_MATCH,as2,pfx)}|{get_reason(Reason.ROA_MATCH,as1,super_pfx)}"
    else:
        _reason = f"{get_reason(Reason.ROA_NOT_MATCH,as2,pfx)}|{get_reason(Reason.ROA_NOT_MATCH,as1,super_pfx)}"

    reason  = _reason
    
    final_result,_ = not_irr_route_filter_subhijack(as1, as2, pfx,super_pfx,timestamp, mongo_client)
    if  not final_result:
        reason = f'{reason}|{_}'
        return final_result,reason
    reason  = f'{reason}|{_}'


    tp = ThreadPool(processes=10)

    def solve_result(result):
        nonlocal final_result
        nonlocal reason
        if final_result and result[0] == False:
            final_result = result[0]
            reason =  f'{reason}|{result[1]}'

    # 出现频次过滤
    if filter_list == 'all' or filter_list['is_too_freqency']:
        tp.apply_async(is_too_freqency,
                    (as1, as2, timestamp, mongo_db, 'sub-possible-hijack'),
                    callback=solve_result,
                    error_callback=exception_happen)

    # import export 过滤
    if filter_list == 'all' or filter_list['is_not_import_or_export']:
        tp.apply_async(is_not_import_or_export, (as1, as2, f'{pfx}_{super_pfx}',timestamp,mongo_client),
                    callback=solve_result,
                    error_callback=exception_happen)

    #商业关系过滤,来自CAIDA AS RANK
    if filter_list == 'all' or filter_list['is_not_in_as_rel_dict']:
        tp.apply_async(is_not_in_as_rel_dict, (as1, as2, f'{pfx}_{super_pfx}'),
                    callback=solve_result,
                    error_callback=exception_happen)

    # 同国家AS过滤
    if filter_list == 'all' or filter_list['not_same_admin_filter']:
        tp.apply_async(not_same_admin_filter, (as1, as2, timestamp, mongo_client),
                        callback=solve_result,
                        error_callback=exception_happen)

    if filter_list == 'all' or filter_list['not_same_org_filter']:
        tp.apply_async(not_same_org_filter, (as1, as2, pfx, mongo_client),
                    callback=solve_result,
                    error_callback=exception_happen)

    if filter_list == 'all' or filter_list['not_same_org_filter_between_as_prefix']:
        tp.apply_async(not_same_org_filter_between_as_prefix,
                    (as1, as2, pfx,timestamp, mongo_client),
                    callback=solve_result,
                    error_callback=exception_happen)


    # 路径过滤:在as_path中处于前后位置
    if filter_list == 'all' or filter_list['is_incorrect_path']:
        tp.apply_async(
            is_incorrect_path,
            (update, super_pfx_after, pfx_after),
            callback=solve_result,
            error_callback=exception_happen)

    if filter_list == 'all' or filter_list['is_not_private_as']:
        tp.apply_async(is_not_private_as,
                    (as1, as2, mongo_client),
                    callback=solve_result,
                    error_callback=exception_happen)
    tp.close()
    tp.join()

    return final_result, reason