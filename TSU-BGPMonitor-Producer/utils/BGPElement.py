import ipaddress


class BGPelement:

    def __init__(self, elem) -> None:
        self.feed = elem
        self.skip = False
        fileds = elem.split('|')
        if len(fileds) < 6 or '{' in elem or '}' in elem:
            self.skip = True
            return
        self.timestamp = fileds[1]
        self.type = fileds[2]
        self.peer_address = fileds[3]
        self.peer_asn = fileds[4]
        self.prefix = ipaddress.ip_network(fileds[5].strip()).exploded
        
        if ':' in self.prefix:
            self.version = 6
        else:
            self.version = 4
            
        if fileds[2] in ['A','B']:
            if len(fileds) < 12:
                self.skip = True
                return
            self.as_path = fileds[6]
            self.next_hop = fileds[8]
            self.community = fileds[11]
        else:
            self.skip = True



    def __str__(self) -> str:
        return str(self.feed)
