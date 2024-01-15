import json
import sys
import os
if sys.argv and len(sys.argv) > 1:
    process_config_path = sys.argv[1]
else:
    process_config_path = f'{os.getcwd()}/config.json'
with open(process_config_path, 'r') as pcf:
    config = json.load(pcf)


def get_config(attr):
    if attr in config:
        return config[attr]
    raise Exception(f'[LOAD CONFIG] {attr} not in config.json')

def get_start_datetime():
    return config['forever_start_datetime']