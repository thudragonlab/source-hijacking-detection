from utils.mongo_util import get_daily_collection

def get_as_info_dict():
    _result = {}
    col = get_daily_collection('as_info')
    result = col.find({})
    for i in result:
        del i['asnDegree']
        del i['announcing']
        _result[i['_id']] = i
    return _result
    


if __name__ == '__main__':
    get_as_info_dict()