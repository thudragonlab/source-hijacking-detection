from enum import Enum

class Reason(Enum):
    AS2_EXPORT_AS1 = 'S:{} export filter {}'
    AS1_EXPORT_AS2 = 'S:{} export filter {}'
    AS1_IMPORT_AS2 = 'S:{} import filter {}'
    AS2_IMPORT_AS1 = 'S:{} import filter {}'
    AS_INFO_SAME_ORG_ID = 'S:AS {},{} Same organization'
    AS_REL_PEER = 'S:peers'
    BOTH_IN_MOAS_SET = 'S:{} both in moasset'
    DDOS_PROVIDER = 'S:{} is AntiDDoS provider'
    HV = "S:The suspect is located upstream of the victim - {}"
    IS_ILLEGAL = 'S:Manually inspected legal MOAS({},{})'
    IS_TOO_FREQENCY = 'S:The probability of jointly holding MOAS exceeds the threshold'
    MOAS_NUM_GT_2 = 'S:MOAS number more than 2'
    PASS_AGGREGATE_ASN = 'S:Pass Aggregate ASN'
    PEER = 'S:peers'
    PREFIX_ALLOCATED = 'S:prefix {} allocated {}'
    PRIVATE_AS = 'S:Private AS{}'
    P2C = 'S:{} is {} Provider'
    ROA_MATCH = "S:({}, {}) aligns in ROA"
    ROA_NOT_MATCH = "W:({}, {}) doesn't align in ROA"
    SIBLINGS = 'S:siblings'
    VH = "S:The victim precedes the suspect on the same path - {}"
    WHOIS_NOT_MATCH = "W:({}, {}) doesn't align in WHOIS"
    WHOIS_MATCH = "S:({}, {}) aligns in WHOIS"
    WHOIS_SAME_ADMIN = 'S:AS {},{} Same admin-c'
    WHOIS_SAME_TECH = 'S:AS {},{} Same tech-c'
    WHOIS_SAME_MNT_LOWER = 'S:AS {},{} Same mnt-lower'
    XH = 'S:Suspect shares upstream provider with victim - {},{}'
    DURATION_0 = 'S:Duration is 0 sec'
    DURATION_GT_48 = 'S:The probability of jointly holding MOAS exceeds the threshold'

def get_reason(key,*args):
    return key.value.format(*args)

    