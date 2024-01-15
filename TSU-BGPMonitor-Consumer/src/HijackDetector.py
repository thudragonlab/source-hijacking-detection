from datetime import datetime
import os
from ipaddress import ip_network
import copy
from src.EventManager import EventManager
from src.RoutingTable import RoutingTable
from utils.log_util import get_logger
from utils.config_util import get_config,get_start_datetime

start_datetime = get_start_datetime()

class HijackDetector:
    """Detect prefix hijack,rout leak and outage.
    read rib file and update file to check prefix moas status and path valley status.
    using as,prefix,rir,whois,rpki knowledge to filter reasonable bgp events
    """

    def __init__(self,hash_0):
        """init basic file path and dict
        """
        self.event_manager = EventManager(hash_0)
        self.routing_table = RoutingTable()
        self.update_counter = 0
        self.rib_prefixes = 0
        self.hash_0 = hash_0
        self.log = get_logger()
        self.jitter_bluk_list = []

        # self.routing_table.add_entry(rec)

        # self.routing_table.init_all_prefix_status()

        self.rib_prefixes = len(self.routing_table.prefix_dict)
  
    def load_onging_data(self):
        self.load_ongoing_event_from_db('ongoing_moas',self.event_manager.running_moas_dict)
        self.load_ongoing_event_from_db('ongoing_hijack',self.event_manager.running_hijack_dict)
        self.load_ongoing_event_from_db('ongoing_submoas', self.event_manager.running_submoas_dict)
        self.load_ongoing_event_from_db('ongoing_subhijack', self.event_manager.running_subhijack_dict)

        for pfx in self.event_manager.running_moas_dict:
            self.routing_table.prefix_dict[pfx].setdefault("is_moas", True)
            self.routing_table.prefix_dict[pfx].setdefault("valid", True)
            self.routing_table.prefix_dict[pfx].setdefault("as_set",set(self.event_manager.running_moas_dict[pfx]['moas_set']))

        for pfx_key in self.event_manager.running_submoas_dict:
            pfx, super_pfx = pfx_key.split('_')

            if pfx in self.event_manager.running_submoas_dict:
                self.routing_table.prefix_dict[pfx].setdefault("valid", True)
                self.routing_table.prefix_dict[pfx].setdefault("as_set",set(self.event_manager.running_submoas_dict[pfx]['moas_set']))
            if super_pfx in self.event_manager.running_submoas_dict:
                self.routing_table.prefix_dict[super_pfx].setdefault("valid", True)
                self.routing_table.prefix_dict[super_pfx].setdefault("as_set",set(self.event_manager.running_submoas_dict[super_pfx]['moas_set']))

            if pfx not in self.event_manager.submoas_dict:
                self.event_manager.submoas_dict[pfx] = []
            self.event_manager.submoas_dict[pfx].append(super_pfx)

            if super_pfx not in self.event_manager.submoas_super_dict:
                self.event_manager.submoas_super_dict[super_pfx] = []
            self.event_manager.submoas_super_dict[super_pfx].append(pfx)

    def load_ongoing_event_from_db(self, col_name, self_dict):
        laun_timestamp = datetime.strptime(start_datetime,'%Y-%m-%d %H:%M').timestamp()
        col = self.event_manager.mongo_db[col_name]
        event_list = col.find({
            'start_timestamp': {
                '$lt': int(laun_timestamp)
            },
            'hash_0': self.hash_0
        })
        for event in event_list:

            del event['_id']
            key = 'dict_k'
            if 'dict_k' not in event:
                key = 'prefix'
            self_dict[event[key]] = event

        self.event_manager.log.debug(
            f'[LOAD ONGOING DATA]  {len(self_dict)} data from collection {col.name} by hash_0 => {self.hash_0}'
        )

    def run(self, rec):

        self.update_counter += 1

        if rec.type == 'state' or rec.type == 'STATE':
            return

        if rec.prefix not in self.routing_table.prefix_dict:
            return
        
        if 'as_set' not in self.routing_table.prefix_dict[rec.prefix]:
            return

        pfx = rec.prefix
        super_pfx = self.get_super_pfx(pfx)
        
        pfx_before = copy.deepcopy(self.routing_table.prefix_dict.get(pfx, None))
        super_pfx_before = copy.deepcopy(self.routing_table.prefix_dict.get(super_pfx, None)) if super_pfx else None
        info_before = copy.deepcopy(self.routing_table.get_prefix_info(pfx))
        
        self.routing_table.update(rec)

        pfx_after = self.routing_table.prefix_dict.get(pfx, None)
        super_pfx_after = self.routing_table.prefix_dict.get(super_pfx, None) if super_pfx else None
        info_after = self.routing_table.get_prefix_info(pfx)

        if info_before['is_moas'] == False and info_after['is_moas'] == True:  # 非moas->moas
            self.event_manager.new_moas_event(info_before, info_after, rec)
            return
        elif info_before['is_moas'] == True and info_after['is_moas'] == True:  # moas -> moas
            self.event_manager.update_moas_event(info_after, rec)
            return
        elif info_before['is_moas'] == True and info_after['is_moas'] == False:  # moas -> 非moas
            self.event_manager.end_moas_event(info_after,rec)  
            return
    
        if super_pfx_before != None and rec.type == 'A' and rec.as_path.split(' ')[-1] not in super_pfx_before['as_set'] and f'{pfx}_{super_pfx}' not in self.event_manager.running_submoas_dict:
            self.event_manager.new_submoas_event(pfx, super_pfx, pfx_before,super_pfx_before, pfx_after,super_pfx_after, rec)

        elif pfx in self.event_manager.submoas_dict and super_pfx in self.event_manager.submoas_super_dict and f'{pfx}_{super_pfx}' in self.event_manager.running_submoas_dict and pfx_after != None:
            self.event_manager.update_submoas_event(pfx, super_pfx, pfx_after,super_pfx_after, rec)

        elif pfx in self.event_manager.submoas_dict and super_pfx in self.event_manager.submoas_super_dict and f'{pfx}_{super_pfx}' in self.event_manager.running_submoas_dict and pfx_after == None:
            self.event_manager.end_submoas_event(pfx, super_pfx, pfx_after,super_pfx_after, rec)

    def get_super_pfx(self, pfx):
        '''
        返回 pfx在路由表中的超前缀
        '''
        pfx = pfx.strip()

        prefix_c = ip_network(pfx)

        # 搜索超前缀也是性能瓶颈，修改数据结构，使用前缀树存储是否能提高速度？（目前使用的是前缀字典）

        for i in range(1, prefix_c.prefixlen):
            super_net = prefix_c.supernet(i)
            if prefix_c.version == 4:
                if super_net.prefixlen < 20:
                    break
            else:
                if super_net.prefixlen < 36:
                    break
            super_prefix = str(super_net)

            if super_prefix in self.routing_table.prefix_dict:
                if 'valid' not in self.routing_table.prefix_dict[super_prefix]:
                    continue
                if self.routing_table.prefix_dict[super_prefix]['valid']:
                    return super_prefix
        return None
