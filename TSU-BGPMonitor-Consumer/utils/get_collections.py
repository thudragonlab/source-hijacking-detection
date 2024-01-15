from utils.mongo_util import get_collection_by_timestamp,get_daily_collection


def get_whois_collection(ts,mongo_client):
    if ts:
        return get_collection_by_timestamp('irr_WHOIS',ts, mongo_client)
    else:
        return get_daily_collection('irr_WHOIS', mongo_client)