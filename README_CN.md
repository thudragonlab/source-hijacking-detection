# BGP劫持检测程序

本程序分为三部分,配合Kafka消息队列实现，只从[rrc00](https://data.ris.ripe.net/rrc00/)这一个采集点获取数据

### Producer

	获取路由数据

### Consumer

	处理路由数据,检测劫持事件并存储数据库

### Script

	获取辅助数据，包括：
- WHOIS
- ROA
- 域名
- ASN信息
- PEER关系数据

  

### 配置文件解析 
详见 `example/example_config.json`

```json
{

"forever_start_datetime": "检测开始时间",
"mail_pass": "报警邮件发送邮箱密钥",
"server_name": "运行服务器标识",
"load_ongoing_data": "是否加载ongoing数据",
"use_local_files": "是否读取本地已存在的文件",
"log_level": "日志级别",
"admin_email": "管理员邮箱",
"roa_url": "ROA验证地址",
"bgpwatch_url": "BGPWatch地址",
"tmp_name": "临时数据存储地址",
"db_config": "数据库信息",
"kafka_config": "kafka信息"
}