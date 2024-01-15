# BGP Monitor

The Process have three parts, implemented in Kafka. Only from One collector [rrc00](https://data.ris.ripe.net/rrc00/) obtains data.


### Producer

	Get router data.

### Consumer

	Process router data, monitor BGP hijack events and save in db.

### Script

	Get Other Data，Includes:
- WHOIS
- ROA
- DOMAIN
- ASN INFO
- AS peers relationship(CAIDA)

  

### Configuration
Detail in `example/example_config.json`

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