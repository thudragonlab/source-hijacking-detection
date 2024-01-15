from collections import defaultdict
import threading
from typing import Dict



class RoutingTable:
    """使用RIB初始化路由表"""

    def __init__(self) -> None:
        self.prefix_dict:Dict[str,Dict] = defaultdict(dict)

    def add_entry(self, rec):
        path = rec.as_path.split(' ')
        is_aggregate  = '[' in path[-1] or '{' in path[-1]
        key = f'{rec.peer_asn}|{rec.peer_address}'
        # if '[' in path[-1] or '{' in path[-1]:  # if the prefix is aggregated
        #             return
        
        self.prefix_dict[rec.prefix].setdefault('first_learned_time', rec.timestamp)
        self.prefix_dict[rec.prefix].setdefault("path_dict", {})
        self.prefix_dict[rec.prefix].setdefault("as_set", set())
        self.prefix_dict[rec.prefix].setdefault("valid", False)
        self.prefix_dict[rec.prefix].setdefault("is_moas", False)
        self.prefix_dict[rec.prefix].setdefault("next_moas_id", 0)
        self.prefix_dict[rec.prefix].setdefault("next_hijack_id", 0)
        self.prefix_dict[rec.prefix].setdefault("last_5_hijack_time", [])
        
        # path_dict {as_path[0]:as_path}
        as_set = self.prefix_dict[rec.prefix]['as_set']
        if not is_aggregate:
            as_set.add(path[-1])
        as_set_len = len(as_set)
        self.prefix_dict[rec.prefix]['valid'] = as_set_len > 0
        self.prefix_dict[rec.prefix]['is_moas'] = as_set_len > 1

        self.prefix_dict[rec.prefix]['path_dict'].update({
            key: rec.as_path
        })

    def update(self, rec):
        '''更新路由表'''
        self.prefix_dict[rec.prefix].setdefault("path_dict", {})
        self.prefix_dict[rec.prefix].setdefault('next_moas_id', 0)
        self.prefix_dict[rec.prefix].setdefault('next_hijack_id', 0)
        self.prefix_dict[rec.prefix].setdefault('last_5_hijack_timestamp', [])
        key = f'{rec.peer_asn}|{rec.peer_address}'
        if rec.type == 'A':
            
            #如果是Add类型 则 更新asn对应的as_path

            self.prefix_dict[rec.prefix]['path_dict'][key] = rec.as_path
            
        else:
            #否则是Withdraw类型 删掉对应的路径
            
            if key in self.prefix_dict[rec.prefix]['path_dict']:
                # print('rec.peer_asn',rec.peer_asn)
                del self.prefix_dict[rec.prefix]['path_dict'][key]
        self.__update_prefix_status(rec.prefix,rec.timestamp)

    # def init_all_prefix_status(self):
    #     for prefix, info in self.prefix_dict.items():
    #         as_set = set()
    #         for path in info['path_dict'].values():
    #             path = path.split(' ')
    #             if len(path) == 0:
    #                 print(path) 
    #             if '[' in path[-1] or '{' in path[-1]:  # if the prefix is aggregated
    #                 continue
    #             as_set.add(path[-1])
    #         info.update({
    #             "valid": len(as_set) > 0,
    #             "as_set": as_set,
    #             "is_moas": len(as_set) > 1, # A MOAS conflict occurs when a particular prefix appears to originate from more than one AS
    #             "next_moas_id": 0,
    #             "next_hijack_id": 0,
    #             "last_5_hijack_time": []
    #         })

    #     #Remove invalid prefix
    #     for prefix, info in list(self.prefix_dict.items()):
    #         if info['valid'] == False:
    #             del self.prefix_dict[prefix]
    #             continue

    #         # prefix_c = ip_network(prefix)
    #         # for i in reversed(range(prefix_c.prefixlen)):
    #         #     super_prefix = str(prefix_c.supernet(i))
    #         #     if super_prefix in self.prefix_dict.keys() and list(as_set)[0] not in self.prefix_dict[super_prefix]['as_set']:
    #         #         info.update({
    #         #             "is_submoas":True,
    #         #             "super_prefix":super_prefix
    #         #         })

    def get_as_set(self, prefix):
        if prefix in self.prefix_dict.keys() and self.prefix_dict[prefix]['valid']:
            return self.prefix_dict[prefix]['is_moas'], self.prefix_dict[prefix]['as_set_dict']
        return False, None

    def get_prefix_info(self, prefix):
        if prefix in self.prefix_dict and self.prefix_dict[prefix]['valid']:
            return self.prefix_dict[prefix]
        return {'is_moas': False,'path_dict':{}}

    def get_path_list(self, prefix):
        if prefix in self.prefix_dict and self.prefix_dict[prefix]['valid']:
            return list(self.prefix_dict[prefix]['path_dict'].values())
        return None

    #和init_all_prefix_status有些重复
    def __update_prefix_status(self, prefix,ts):
        '''更新prifix的is_moas状态'''
        as_set = set()

        for path in self.prefix_dict[prefix]['path_dict'].values():
            path = path.split(' ')
            if '[' in path[-1] or '{' in path:  # if the prefix is aggregated
                continue
            as_set.add(path[-1])

        self.prefix_dict[prefix].update({
            "valid": len(as_set) > 0,
            "as_set": as_set,
            "is_moas": len(as_set) > 1,
            # "next_moas_id":0,
            # "next_hijack_id":0,
        })
        if self.prefix_dict[prefix]['valid'] == False:
            del self.prefix_dict[prefix]

    def __iter__(self):
        return self.prefix_dict

    def print_(self):
        print(len(self.prefix_dict))
        threading.Timer(5, self.print_).start()
