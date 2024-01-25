## Source Hijacking Detection

Source Hijacking Detection is a real-time hijacking detecting system based on MOAS(Multi-Origin Autonomous System) event. It monitor real-time MOAS event in the global BGP routing table and then use domain knowledge, including information from Whois, ROA (Route Origin Authorization), AS (Autonomous System) relationships, etc., along with predefined rules, to filter out benign events and identify potential hijacking events. The project uses produce-consumer architecture,  the producer gets route data from BGP route feed such as RIPE RIS、RouteViews and Our CGTF RIS([Index of / (cgtf.net)](https://bgp.cgtf.net/)) and the consumer processes route, monitors BGP hijacking events and save them to database. Source Hijacking Detection is only for hijacking detecting, if you want a web-system with frontend,  please refer to  bgpwatch-frontend and bgpwatch-backend.

The BGPWatch platform has been developed by researchers and engineers from 19 countries/economies and funded by APNIC Foundation and the Chinese Government. The platform is accessible to the public at https://bgpwatch.cgtf.net.

The platform supports BGP hijack detection, ensures swift response times, sends event warnings via email, assesses the severity of events, and provides event replay capabilities, which are all designed to effectively assist network operators. 

Additionally, the platform has developed various tools useful for network operators to monitor the network, including a dashboard displaying the key AS information, showing forward, reverse and bi-directional routing path, and supporting subscriptions.

## Project Structure

```txt
├── config.json								# Configuration file
├── example								# Example configuration file
├── script								# Python script
│   ├── as_info.py
│   ├── caida.py
│   ├── domain.py
│   ├── roa.py
│   └── whois.py
│   ├── utils
├── static								# Static resource
├── TSU-BGPMonitor-Consumer						# Consumer
│   ├── logs								# Consumer log files
│   ├── main.py								# Consumer entry file
│   ├── src								# Consumer source code
│   └── utils								# Consumer utils code
└── TSU-BGPMonitor-Producer						# Producer
    ├── getRoutingData.py					
    ├── main.py								# Producer entry file
    ├── Producer.py
	├── data							# Producer rib path	
	├── logs							# Producer log files
    └── utils								# Producer utils code
```

## Requirements

You need to setup a kafka message queue as proxy, a database for hijacking storage, and have python3.8 installed. 



## Installing and running
### install python packages

```shell
pip3 install -r requirements
```


### modify config file
Modify example/example_config.json as you see fit.

```json
{

"forever_start_datetime": "Start datetime",
"mail_pass": "email password",
"server_name": "Server Name",
"load_ongoing_data": "Whether use ongoing file",
"use_local_files": "Whether use local file",
"log_level": "Log level",
"admin_email": "The email of Administer",
"roa_url": "ROA URL",
"bgpwatch_url": "BGPWATCH URL",
"tmp_name": "TEMP data save path",
"db_config": "DB info",
"kafka_config": "Kafka info"
}
```

### Start Producer

```shell
tmux 
python3 TSU-BGPMonitor-Producer/main.py
```

### Start Consumer

```shell
tmux 
python3 TSU-BGPMonitor-Consumer/main.py
```

### Output Event format
```javascript
{
    "hash_0" : "0", 								# Partition key of kafka
    "event_id" : "168.253.248.0/24-moas1701388889", 				# Event id
    "prefix" : "168.253.248.0/24", 						# Prefix
    "start_timestamp" : 1701388889.0, 								
    "start_datetime" : "2023-12-01 00:01:29",						
    "moas_set" : [ "37294", "36913"],						# Moas ASN
    "suspicious_as" : "37294",										
    "before_as" : "36913",											
    "before_as_country" : "MW",										
    "before_as_description" : "TELEKOM-NETWORKS-MALAWI",			
    "suspicious_as_country" : "MW",
    "suspicious_as_description" : "TNM",
    "is_hijack" : false,							# Is hijack event
    "reason" : "S:(36913, 37294) aligns in ROA",				# The reason of hijack event
    "level" : "low",								# Event level
    "level_reason" : "",							# Event level reason
    "after_as" : "37294",							# The after ASN when event end
    "end_timestamp" : 1701388951.0,
    "end_datetime" : "2023-12-01 00:02:31",
    "duration" : "0:1:2",							# The duration of event
    "event_id_list" : [ 							# Aggregated event id
        "168.253.248.0/24-moas1701388889", 
        "168.253.255.0/24-moas1701388889"
    ],
    "prefix_list" : [ 								# Aggregated event prefix
        "168.253.248.0/24", 
        "168.253.255.0/24"
    ],
    "websites" : {								# The websites relation to prefix
        "168.253.248.0/24" : [],
        "168.253.255.0/24" : []
    }
}

```

## Related links

[BGP Watch (cgtf.net)](https://bgpwatch.cgtf.net/#/)

[thudragonlab/bgpwatch-frontend: Frontend repository for BGPWatch (github.com)](https://github.com/thudragonlab/bgpwatch-frontend)

[thudragonlab/bgpwatch-backend (github.com)](https://github.com/thudragonlab/bgpwatch-backend)

[(20) BGPWatch: BGP Routing Analysis and Diagnostic Platform_Manual Video_20240119 - YouTube](https://www.youtube.com/watch?v=0vX6i6XOTL4)



