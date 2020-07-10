# pyDragonHive

A python script to send Wazuh alerts to TheHive, adding observables, tags and alert metadata.

You can pass data to this script via CLI arguments.

### Deployment

**Dependencies**
* Python36
* click
* requests

**TheHive API Details**

* Change `HIVE_URL` on like 174 to your TheHive URL.
* Change `HIVE_API_KEY` on like 175 to your hive API key. make sure the associated user as the **Allow alerts creation** permission.

**CLI Arguments**

Please make sure to specify ALL the below CLI arguments when running the script, passing "<MISSING VALUE>" where data is not present. Using alerting systems like elastAlert will fill in the "<MISSING VALUE>" for you when the elasticSearch event does not contain a field.
  
All the below fields should be passed as a string, their associated fields are self-explanatory.
  
* --agent_id
* --agent_name
* --agent_ip
* --rule_description
* --rule_id
* --rule_level
* --rule_groups
* --data_data_srcip
* --data_data_web_srcip
* --data_data_eventchannel_srcip
* --data_full_log
* --data_fim_sha256
* --alert_elk_id
* --alert_wazuh_id
* --alert_datetime

The script will use one of the source IP fields, taking the first that matches in the order data_data_srcip, data_data_web_srcip or data_data_eventchannel_srcip. If matched, this field will be validated using the socket library to check that it is a valid IP address.
  
### Observables

The script will attempt to generate and add observables for

* Agent IP with tags for Agent Name, Agent ID
* FIM sha256 with tags for sha256_after (Will only be added for FIM alerts)


### The alert in the hive will follow the below format

## Wazuh Alert

**Agent Details**

ID: ```{agent_id}```

Name: ```{agent_name}```

IP: ```{agent_ip}```

**Rule Details**

Rule Description: ```{rule_description}```

**Event Details**

Date/time: ```{alert_datetime} ```

Rule ID: ```{rule_id}```

Rule Level: ```{rule_level}```

Source IP: ```{srcip}```

Full Log:```\n\n{data_full_log}```

elasticSearch Document ID: ```{alert_elk_id}```

Wazuh Event ID: ```{alert_wazuh_id}```
