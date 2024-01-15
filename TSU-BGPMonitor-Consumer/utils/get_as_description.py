from utils.mongo_util import get_collection_by_name, get_daily_collection
from utils.manager_util import get_manager

manager = get_manager()
cache = manager.dict()

def get_as_description(asn,mongo_client):
    if asn in cache:
        return cache[asn]
    col = get_daily_collection('irr_WHOIS', mongo_client)
    condition = {'aut-num':{'$in':[int(asn),f'AS{asn}']},'as-name':{'$exists':True}}
    asn_item = col.find_one(condition,{'as-name':1})
    if asn_item and 'as-name' in asn_item:
        cache[asn] = asn_item['as-name']
        return asn_item['as-name']
    else:
        return ''
