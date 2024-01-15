from utils.get_as_rel_data import get_as_rel_data
from utils.get_as_info_dict import get_as_info_dict
from utils.get_important_as import get_important_as
from utils.log_util import get_logger

class KnoledgeBase:
    as_dict = {}
    important_as_dict = {}
    important_prefix_dict = {}
    as_prefix_dict = {}
    as_rel_dict = {}
    roa_dict = {}
    as_sibling = {}
    as_info_dict = {}
    log = get_logger()
    
    def __init__(self):
        self.important_as_dict = get_important_as()

        self.as_info_dict = get_as_info_dict()
        self.log.debug(f'[INIT] Load as info dict, {len(self.as_info_dict)} data')
        
        # 从数据库里面caida-as-relationship读取最小的数据
        self.as_rel_dict = get_as_rel_data()
        self.log.debug(f'[INIT] Load as relationship dict, {len(self.as_rel_dict)} data')
        
knowledge_base = KnoledgeBase()
print('load from json files')

def get_as_country(asn):
    if asn in knowledge_base.as_info_dict:
        if 'country' in knowledge_base.as_info_dict[asn]:
            if 'iso' in knowledge_base.as_info_dict[asn]['country']:
                return knowledge_base.as_info_dict[asn]['country']['iso']
    return ""
