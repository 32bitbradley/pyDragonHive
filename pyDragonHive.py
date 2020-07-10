#!/usr/bin/python3
# This script will generate a TheHive alert using the API
import json, click, socket, requests, re
from os import urandom
import logging
urllib3.disable_warnings()

# Get command line data
@click.command()
@click.option("--agent_id")
@click.option("--agent_name")
@click.option("--agent_ip")
@click.option("--rule_description")
@click.option("--rule_id")
@click.option("--rule_level")
@click.option("--rule_groups")
@click.option("--data_data_srcip")
@click.option("--data_data_web_srcip")
@click.option("--data_data_eventchannel_srcip")
@click.option("--data_full_log")
@click.option("--data_fim_sha256")
@click.option("--alert_elk_id")
@click.option("--alert_wazuh_id")
@click.option("--alert_datetime")
@click.option("--debug", is_flag=True)

def GenerateHiveAlert(agent_id, agent_name, agent_ip, rule_description, rule_id, rule_level, rule_groups, data_data_srcip, data_data_web_srcip, data_data_eventchannel_srcip, data_full_log, data_fim_sha256, alert_elk_id, alert_wazuh_id, alert_datetime, debug):
    log_file = "wazuh_hive.log"
    if (debug):
        logging.basicConfig(level=logging.DEBUG, format='%(asctime)s %(levelname)s: %(message)s', datefmt='%d-%m-%Y %H:%M:%S', filename=log_file, filemode='a')
    else:
        logging.basicConfig(level=logging.INFO, format='%(asctime)s %(levelname)s: %(message)s', datefmt='%d-%m-%Y %H:%M:%S', filename=log_file, filemode='a')

    logging.debug(f'CLI Args: {agent_id}, {agent_name}, {agent_ip}, {rule_description}, {rule_id}, {rule_level}, {rule_groups}, {data_data_srcip}, {data_data_web_srcip}, {data_data_eventchannel_srcip}, {data_full_log}, {data_fim_sha256}, {alert_elk_id}, {alert_wazuh_id}, {alert_datetime}')
    
    def GetIPType(data_data_srcip, data_data_web_srcip, data_data_eventchannel_srcip):
        def ValidateIP(ip):
            def is_valid_ipv4_address(ip):
                try:
                    socket.inet_pton(socket.AF_INET, ip)
                except AttributeError:  # no inet_pton here, sorry
                    try:
                        socket.inet_aton(ip)
                    except socket.error:
                        return False
                    return ip.count('.') == 3
                except socket.error:  # not a valid address
                    return False

                return True
            def is_valid_ipv6_address(ip):
                try:
                    socket.inet_pton(socket.AF_INET6, ip)
                except socket.error:  # not a valid address
                    return False
                return True
            if is_valid_ipv4_address(ip):
                logging.debug(f"Ip address is a valid IPv4: {ip}")
                return True
            elif is_valid_ipv6_address(ip):
                logging.debug(f"Ip address is a valid IPv6: {ip}")
                return True
            else:
                logging.debug(f"Ip address is NOT a valid IPv4 or IPv6: {ip}")
                return False
        if (data_data_srcip != "<MISSING VALUE>"):
            srcip = data_data_srcip
            logging.debug(f'Set Attacking IP to data_srcip: {data_data_srcip}')
            if ValidateIP(srcip) is False:
                return False
        elif (data_data_web_srcip != "<MISSING VALUE>"):
            srcip = data_data_web_srcip
            logging.debug(f'Set Attacking IP to data_data_web_srcip: {data_data_web_srcip}')
            if ValidateIP(srcip) is False:
                return False

        elif (data_data_eventchannel_srcip != "<MISSING VALUE>"):
            srcip = data_data_eventchannel_srcip
            logging.debug(f'Set Attacking IP to data_data_eventchannel_srcip: {data_data_eventchannel_srcip}')
            if ValidateIP(srcip) is False:
                return False
        else:
            srcip = False
            logging.debug(f'No Valid attacking IP was found.')
        return srcip
    def CheckWhitelist(agent_id,rule_id,srcip,data_full_log):
        with open("whitelist.json","r") as f:
            counter = 0
            for line in f:
                #load_data = line.read()
                whitelist = json.loads(line)
                counter = counter + 1
                if agent_id == whitelist['agent_id']:
                    logging.debug(f'Agent ID {agent_id} found in whitelist on line {counter}')
                    if rule_id == whitelist['rule_id'] or whitelist['rule_id'] == 'all':
                        logging.debug(f'Rule ID {rule_id} found in whitelist on line {counter}')
                        if srcip == whitelist['source_ip'] or whitelist['source_ip'] == 'all':
                            logging.debug(f'Srcip {srcip} found in whitelist on line {counter}')
                            if whitelist['full_log_regex'] == 'all':
                               logging.debug(f"Regex {whitelist['full_log_regex']} matched on line {counter}")
                               return True
                            elif re.match(whitelist['full_log_regex'], data_full_log):
                                logging.debug(f"Regex {whitelist['full_log_regex']} matched on line {counter}")
                                return True
                            else:
                                logging.debug(f"Whitelist regex not matched in whitelist on line {counter}")
                        else:
                            logging.debug(f"Srcip not matched in whitelist on line {counter}")
                    else:
                        logging.debug(f"Rule ID not matched in whitelist on line {counter}")
                else:
                    logging.debug(f"Agent ID not matched in whitelist on line {counter}")
        return False
    def BuiltObservables(agent_id, agent_name, agent_ip, srcip, data_fim_sha256, rule_groups):
        #The agent name obvervable will allways be here, so we can use this as the end item in the JSON string, then prepend others to the obvervables variable
        artifact_agentIP = json.loads('{ }')
        artifact_agentIP["dataType"] = "ip"
        artifact_agentIP["data"] = agent_ip
        artifact_agentIP["tags"] = []
        artifact_agentIP["tags"].append("Type: gent_ip")
        artifact_agentIP["tags"].append(f"ID: {agent_id}")
        artifact_agentIP["tags"].append(f"Name: {agent_name}")
        artifact_srcip = None
        artifact_sha256 = None
        logging.debug(f'Set artifact_agentIP: {json.dumps(artifact_agentIP)}')
        # Build attacking IP obserables if a srcip is found and passed
        if (srcip != False):
            artifact_srcip = json.loads('{ }')
            artifact_srcip["dataType"] = "ip"
            artifact_srcip["data"] = srcip
            groups_array = rule_groups.split("[")[1].split("]")[0].split(",")
            groups_array = [w.replace("'","") for w in groups_array]
            groups_array = [w.replace(" ","") for w in groups_array]
            artifact_srcip["tags"]= groups_array
            artifact_srcip["tags"].append("attacking_ip")
            logging.debug(f'Set artifact_srcip: {json.dumps(artifact_agentIP)}')
        # Build FIM has obervable if not MISSING VALUE
        if (data_fim_sha256 != "<MISSING VALUE>"):
            artifact_sha256 = json.loads('{ }')
            artifact_sha256["dataType"] = "hash"
            artifact_sha256["data"] = data_fim_sha256
            groups_array = rule_groups.split("[")[1].split("]")[0].split(",")
            groups_array = [w.replace("'","") for w in groups_array]
            artifact_sha256["tags"]= groups_array
            artifact_sha256["tags"].append("sha256_after")
            logging.debug(f'Set artifact_sha256: {json.dumps(artifact_sha256)}')
        return artifact_agentIP, artifact_srcip, artifact_sha256
    def BuildRequestBody(agent_id, agent_name, agent_ip, srcip, data_fim_sha256, rule_groups, artifact_agentIP, artifact_srcip, artifact_sha256):
        alert = json.loads('{ }')
        alert["title"] = agent_id + " -> " + rule_description
        alert["type"] = "Wazuh_Alert"
        alert["source"] = agent_name
        alert["sourceRef"] = urandom(5).hex()
        alert["severity"] = 1
        alert["tlp"] = 1
        alert["description"] = f"## Wazuh Alert \n\n\n**Agent Details**\n\n\nID: ```{agent_id}```\n\nName: ```{agent_name}```\n\nIP: ```{agent_ip}```\n\n\n**Rule Details**\n\n\nRule Description: ```{rule_description}```\n\n\n**Event Details**\n\nDate/time: ```{alert_datetime} ```\n\nRule ID: ```{rule_id}```\n\nRule Level: ```{rule_level}```\n\n\nSource IP: ```{srcip}```\n\n\nFull Log:\n\n```\n\n{data_full_log}```\n\nelasticSearch Document ID: ```{alert_elk_id}```\n\nWazuh Event ID: ```{alert_wazuh_id}```"
        alert["tags"] = []
        alert["tags"].append("Rule ID:" + rule_id)
        alert["tags"].append("Rule Level:" + rule_level)
        alert["tags"].append("Agent ID:" + agent_id)
        alert["artifacts"] = []
        alert["artifacts"].append(artifact_agentIP)
        if (srcip != False):
            alert["artifacts"].append(artifact_srcip)
        if (data_fim_sha256 != "<MISSING VALUE>"):
            alert["artifacts"].append(artifact_sha256)
        logging.debug(f'Built alert: {json.dumps(alert)}')
        return alert
    logging.info(f'Running for Wazuh ID: {alert_wazuh_id}')
    srcip = GetIPType(data_data_srcip, data_data_web_srcip, data_data_eventchannel_srcip)
    if CheckWhitelist(agent_id,rule_id,srcip,data_full_log) == False:
        artifact_agentIP, artifact_srcip, artifact_sha256 = BuiltObservables(agent_id, agent_name, agent_ip, srcip, data_fim_sha256, rule_groups)
        alert = BuildRequestBody(agent_id, agent_name, agent_ip, srcip, data_fim_sha256, rule_groups, artifact_agentIP, artifact_srcip, artifact_sha256)
        host = "https://HIVE_URL/api/alert"
        headers = {"Content_Type": "application/json", "Authorization":"Bearer HIVE_API_KEY"}
        logging.debug(f'Sending alert: {json.dumps(alert)}')
        r = requests.post(host, json=alert, headers=headers, verify=False)
        logging.debug(f'Received response from TheHive API: {r.text}')
        return True
    else:
        logging.debug(f'Event was whitelisted.')
        return True
GenerateHiveAlert()