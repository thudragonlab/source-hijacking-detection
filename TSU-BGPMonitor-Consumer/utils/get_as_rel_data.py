
from utils.mongo_util import get_daily_collection

def get_as_rel_data():
    result = {}
    col = get_daily_collection('serial1')
    for i in col.find():
        asn = i['_id']
        customer = i['customer-ases']
        provider = i['provider-ases']
        peer = i['peer-ases']

        if asn not in result:
            result[asn] = {"provider":[],"customer":[],"peer":[]}
            result[asn]['provider'] = provider
            result[asn]['customer'] = customer
            result[asn]['peer'] = peer
    
    return result