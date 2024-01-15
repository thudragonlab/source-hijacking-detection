import math

from utils.common_util import timestamp2date
from utils.log_util import get_logger

aggregate_time_interval = 300

def aggregate_subhijack_events(e_list, mycol):
    '''
        原来通过fp_out存入文件中，现在改为存入到mongoDB中
    '''
    aggregated_event_dict = {}
    # print('Processing %s %s data' % (len(e_list),mycol.name))
    for unit_event in e_list:
        key = '%s_%s-%s_%s' % (unit_event['victim_as'],
                               unit_event['hijack_as'],
                               math.ceil(unit_event['start_timestamp'] / aggregate_time_interval),
                               math.ceil(unit_event['end_timestamp'] / aggregate_time_interval))
        if key not in aggregated_event_dict:
            aggregated_event_dict[key] = unit_event
            aggregated_event_dict[key]['event_id_list'] = [unit_event['event_id']]
            aggregated_event_dict[key]['start_datetime'] = timestamp2date(
                aggregated_event_dict[key]['start_timestamp'])
            aggregated_event_dict[key]['end_datetime'] = timestamp2date(
                aggregated_event_dict[key]['end_timestamp'])
            if aggregated_event_dict[key]['end_timestamp'] == 'Unknown':
                aggregated_event_dict[key]['end_timestamp'] = -1
                aggregated_event_dict[key]['duration'] = -1
            aggregated_event_dict[key]['prefix_list'] = [[
                unit_event['subprefix'], unit_event['prefix']
            ]]
            aggregated_event_dict[key]['websites'] = unit_event['websites_in_prefix']

            if 'websites_in_prefix' in aggregated_event_dict[key]:
                del aggregated_event_dict[key]['websites_in_prefix']
            

            # TODO limit replay times 20
            if 'replay' in aggregated_event_dict[key]:
                shortly_replay(aggregated_event_dict, key)
        else:
            aggregated_event_dict[key]['event_id_list'].append(unit_event['event_id'])
            aggregated_event_dict[key]["prefix_list"].append(
                [unit_event['subprefix'], unit_event['prefix']])
            
            aggregated_event_dict[key]['websites'].update({
                unit_event['prefix']:
                unit_event['websites_in_prefix'][unit_event['prefix']],
            })

            aggregated_event_dict[key]['websites'].update({
                unit_event['subprefix']:
                unit_event['websites_in_prefix'][unit_event['subprefix']],
            })
            
            if lower_level(aggregated_event_dict[key]['level'],
                           unit_event['level']):
                aggregated_event_dict[key]['level'] = unit_event['level']
                aggregated_event_dict[key]['level_reason'] = unit_event[
                    'level_reason']

            if 'websites_in_prefix' in aggregated_event_dict[key]:
                del aggregated_event_dict[key]['websites_in_prefix']

    # 将数据存到mongoDB中
    # print("Data writting to mongoDB.... %s" % mycol.name)
    if (len(aggregated_event_dict) != 0):
        mycol.insert_many(aggregated_event_dict.values())


def aggregate_moas_events(e_list, mycol):
    '''
        原来通过fp_out存入文件中，现在改为存入到mongoDB中
    '''
    log = get_logger()
    aggregated_event_dict = {}
    # ('Processing %s %s data' % (len(e_list),mycol.name))
    for unit_event in e_list:
        key = '%s_%s-%s_%s' % (unit_event['before_as'],
                               unit_event['suspicious_as'],
                               math.ceil(unit_event['start_timestamp'] / aggregate_time_interval),
                               math.ceil(unit_event['end_timestamp'] / aggregate_time_interval))
        log.debug(f'key => {key}')
        if key not in aggregated_event_dict:
            aggregated_event_dict[key] = unit_event
            aggregated_event_dict[key]['event_id_list'] = [unit_event['event_id']]
            aggregated_event_dict[key]['start_datetime'] = timestamp2date(
                aggregated_event_dict[key]['start_timestamp'])
            aggregated_event_dict[key]['end_datetime'] = timestamp2date(
                aggregated_event_dict[key]['end_timestamp'])
            if aggregated_event_dict[key]['end_timestamp'] == 'Unknown':
                aggregated_event_dict[key]['end_timestamp'] = -1
                aggregated_event_dict[key]['duration'] = -1
            aggregated_event_dict[key]['prefix_list'] = [unit_event['prefix']]
            if  'websites_in_prefix' in unit_event:
                aggregated_event_dict[key]['websites'] = {
                    unit_event['prefix']: unit_event['websites_in_prefix']
                }

            if 'websites_in_prefix' in aggregated_event_dict[key]:
                del aggregated_event_dict[key]['websites_in_prefix']
        else:
            aggregated_event_dict[key]['event_id_list'].append(unit_event['event_id'])
            aggregated_event_dict[key]["prefix_list"].append(
                unit_event["prefix"])
            
            if  'websites_in_prefix' in unit_event:
                aggregated_event_dict[key]['websites'].update({
                    unit_event['prefix']:
                    unit_event['websites_in_prefix'],
                })

            if lower_level(aggregated_event_dict[key]['level'],
                           unit_event['level']):
                aggregated_event_dict[key]['level'] = unit_event['level']
                aggregated_event_dict[key]['level_reason'] = unit_event[
                    'level_reason']

            if 'websites_in_prefix' in aggregated_event_dict[key]:
                del aggregated_event_dict[key]['websites_in_prefix']

    # 将数据存到mongoDB中
    # print("Data writting to mongoDB.... %s" % mycol.name)
    if (len(aggregated_event_dict) != 0):
        mycol.insert_many(aggregated_event_dict.values())


def aggregate_submoas_events(e_list, mycol):
    '''
        原来通过fp_out存入文件中，现在改为存入到mongoDB中
    '''
    aggregated_event_dict = {}
    # print('Processing %s %s data' % (len(e_list),mycol.name))
    for unit_event in e_list:
        key = '%s_%s-%s_%s' % (unit_event['before_as'],
                               unit_event['suspicious_as'],
                               math.ceil(unit_event['start_timestamp'] / aggregate_time_interval),
                               math.ceil(unit_event['end_timestamp'] / aggregate_time_interval))
        if key not in aggregated_event_dict:
            aggregated_event_dict[key] = unit_event
            aggregated_event_dict[key]['event_id_list'] = [unit_event['event_id']]
            aggregated_event_dict[key]['start_datetime'] = timestamp2date(
                aggregated_event_dict[key]['start_timestamp'])
            aggregated_event_dict[key]['end_datetime'] = timestamp2date(
                aggregated_event_dict[key]['end_timestamp'])
            if aggregated_event_dict[key]['end_timestamp'] == 'Unknown':
                aggregated_event_dict[key]['end_timestamp'] = -1
                aggregated_event_dict[key]['duration'] = -1
            aggregated_event_dict[key]['prefix_list'] = [[
                unit_event['subprefix'], unit_event['prefix']
            ]]
            if 'websites_in_prefix' in unit_event:
                aggregated_event_dict[key]['websites'] = unit_event['websites_in_prefix']

            if 'websites_in_prefix' in aggregated_event_dict[key]:
                del aggregated_event_dict[key]['websites_in_prefix']
        else:
            aggregated_event_dict[key]['event_id_list'].append(unit_event['event_id'])
            aggregated_event_dict[key]["prefix_list"].append(
                [unit_event['subprefix'], unit_event['prefix']])
            aggregated_event_dict[key]['websites'].update({
                unit_event['prefix']:
                unit_event['websites_in_prefix'],
            })
            if lower_level(aggregated_event_dict[key]['level'],
                           unit_event['level']):
                aggregated_event_dict[key]['level'] = unit_event['level']
                aggregated_event_dict[key]['level_reason'] = unit_event[
                    'level_reason']

            if 'websites_in_prefix' in aggregated_event_dict[key]:
                del aggregated_event_dict[key]['websites_in_prefix']

    # 将数据存到mongoDB中
    # print("Data writting to mongoDB.... %s" % mycol.name)
    if (len(aggregated_event_dict) != 0):
        mycol.insert_many(aggregated_event_dict.values())


def aggregate_hijack_events(e_list, mycol):
    '''
        原来通过fp_out存入文件中，现在改为存入到mongoDB中
    '''
    aggregated_event_dict = {}
    # print('Processing %s %s data' % (len(e_list),mycol.name))
    
    for unit_event in e_list:
        key = '%s_%s-%s_%s' % (unit_event['victim_as'],
                               unit_event['hijack_as'],
                               math.ceil(unit_event['start_timestamp'] / aggregate_time_interval),
                               math.ceil(unit_event['end_timestamp'] / aggregate_time_interval))
        if key not in aggregated_event_dict:
            aggregated_event_dict[key] = unit_event
            aggregated_event_dict[key]['event_id_list'] = [unit_event['event_id']]
            aggregated_event_dict[key]['start_datetime'] = timestamp2date(
                aggregated_event_dict[key]['start_timestamp'])
            aggregated_event_dict[key]['end_datetime'] = timestamp2date(
                aggregated_event_dict[key]['end_timestamp'])
            if aggregated_event_dict[key]['end_timestamp'] == 'Unknown':
                aggregated_event_dict[key]['end_timestamp'] = -1
                aggregated_event_dict[key]['duration'] = -1
            aggregated_event_dict[key]['prefix_list'] = [
                aggregated_event_dict[key]["prefix"]
            ]
            aggregated_event_dict[key]['websites'] = {
                unit_event['prefix']: unit_event['websites_in_prefix']
            }

            if 'websites_in_prefix' in aggregated_event_dict[key]:
                del aggregated_event_dict[key]['websites_in_prefix']
            
            # TODO limit replay times 20
            if 'replay' in aggregated_event_dict[key]:
                shortly_replay(aggregated_event_dict, key)

        else:
            aggregated_event_dict[key]['event_id_list'].append(unit_event['event_id'])
            if isinstance(unit_event['websites_in_prefix'],dict):
                unit_event['websites_in_prefix'] = list(unit_event['websites_in_prefix'].values())

            aggregated_event_dict[key]["prefix_list"].append(
                unit_event["prefix"])
            
            if unit_event['prefix'] in aggregated_event_dict[key]['websites']:
                aggregated_event_dict[key]['websites'] = {
                    unit_event['prefix']: list(set(aggregated_event_dict[key]['websites'][unit_event['prefix']] + unit_event['websites_in_prefix']))
                }   

            if lower_level(aggregated_event_dict[key]['level'],
                           unit_event['level']):
                aggregated_event_dict[key]['level'] = unit_event['level']
                aggregated_event_dict[key]['level_reason'] = unit_event[
                    'level_reason']

            if 'websites_in_prefix' in aggregated_event_dict[key]:
                del aggregated_event_dict[key]['websites_in_prefix']

    # 将数据存到mongoDB中
    # print("Data writting to mongoDB.... %s" % mycol.name)
    if (len(aggregated_event_dict) != 0):
        mycol.insert_many(aggregated_event_dict.values())



def shortly_replay(aggregated_event_dict, key):
    replay_len = len(aggregated_event_dict[key]['replay'])
    if replay_len > 20:
        new_replay = {}
        index_offset = len(aggregated_event_dict[key]['replay'])/20
        print(f'[Running log] [{aggregated_event_dict[key]["start_datetime"]}] replay len > 20 ,len => {replay_len}, save 20 replay, index_offset => {index_offset}')
        old_replay_list = list(aggregated_event_dict[key]['replay'].items())
        for i in range(0,20):
            _key = old_replay_list[math.floor(i * index_offset)][0]
            _value = old_replay_list[math.floor(i * index_offset)][1]
            new_replay[_key] = _value
        if math.floor(i * index_offset) != replay_len - 1:
            _key = old_replay_list[replay_len - 1][0]
            _value = old_replay_list[replay_len - 1][1]
            new_replay[_key] = _value
        aggregated_event_dict[key]['replay'] = new_replay


def lower_level(a, b):
    if a == 'low':
        return True
    if a == 'high':
        return False
    if b == 'low':
        return False
    else:
        return True