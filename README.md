# Polkascan PRE Harvester
Polkascan PRE Harvester Python Application

## Description
The Polkascan PRE Harvester Application transforms a Substrate node's raw data into relational data for various classes of objects, such as: blocks, runtime metadata entities, extrinsics, events and various runtime data entities, such as: timestamps, accounts and balances.

## License
https://github.com/polkascan/polkascan-pre-harvester/blob/master/LICENSE

## **接口调用说明**
### 1. /process ###
Method: POST  
说明：从链上获取区块信息，并将相关数据写入数据库data_block, data_event, data_extrinsic, data_log表  
参数：block_id | block_hash （均为16进制）  
返回值：   
&emsp;&emsp;&emsp;result: added | already exist  
&emsp;&emsp;&emsp;parentHash: 父区块Hash  

### 2. /status ###
Methos: GET  
说明：获取当前数据库中缺失的区块信息  
参数：无   
返回值：  
&emsp;&emsp;&emsp;status: success  
&emsp;&emsp;&emsp;data: 数据库中已有的最新区块ID和缺失的区块ID范围，JSON数组格式 from - to  

### 3. /sequence ###
Method: POST  
说明：从链上获取区块统计信息，并将相关数据写入数据库data_block_total表  
参数：block_id | block_hash （均为16进制）  
返回值：   
&emsp;&emsp;&emsp;result: added | already exist  
&emsp;&emsp;&emsp;parentHash: 父区块Hash