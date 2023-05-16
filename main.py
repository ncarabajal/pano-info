import csv
import re
from panos.panorama import Panorama, DeviceGroup
from panos.policies import PreRulebase, PostRulebase, SecurityRule, NatRule
from netmiko import ConnectHandler, SSHDetect
import time

PANORAMA_IP = "device-ip"
USERNAME = "username"
PASSWORD = "password"

def fetch_rules(device_group, rule_type, policy_type, panorama):
    rulebase_class = PreRulebase if rule_type == 'pre-rulebase' else PostRulebase
    rulebase = rulebase_class()
    device_group.add(rulebase)
    rules = SecurityRule.refreshall(rulebase, add=True) if policy_type == 'security' else NatRule.refreshall(rulebase, add=True)
    disabled_statuses = get_disabled_statuses(rules, panorama, device_group, rule_type, policy_type)
    return rules, disabled_statuses

def get_disabled_statuses(rules, panorama, device_group, rule_type, policy_type):
    rulebase_tree = panorama.xapi.get(xpath=f"/config/devices/entry[@name='localhost.localdomain']/device-group/entry[@name='{device_group.name}']/{rule_type}/{policy_type}")
    disabled_statuses = {}
    for rule in rules:
        rule_xml = rulebase_tree.find(f".//entry[@name='{rule.name}']")
        if rule_xml is not None:
            disabled_element = rule_xml.find('./disabled')
            disabled_statuses[rule.name] = disabled_element is not None and disabled_element.text == 'yes'
    return disabled_statuses

def get_rule_usage(device_group, rule_type, policy_type, ssh):
    try:
        cmd = f"show rule-hit-count device-group {device_group.name} {rule_type} {policy_type} rules all"
        response_text = ssh.send_command(cmd, expect_string=r'[>#]')
        time.sleep(5)
        rule_usage_data = {}
        for line in response_text.strip().split("\n")[2:]:
            match = re.match(r"^(.+?)\s+(Used|Unused|Partially)\s", line)
            if match:
                rule_name, rule_usage = match.groups()
                rule_usage_data[rule_name] = rule_usage
        return rule_usage_data
    except Exception as e:
        print(f"Error fetching rule usage data: {type(e).__name__}: {str(e)}")
        return {}

def write_rules_to_csv(file_name, device_groups, panorama, ssh, policy_type):
    if policy_type == 'security':
        fieldnames = ['Device-Group', 'Rule Type', 'Rule Name', 'Tags', 'Source Zone', 'Source Address', 'Source User', 'Source Devices', 'Destination Zone', 'Destination Address', 'Destination Devices', 'Application', 'Service', 'URL Category', 'Action', 'Profile Group', 'Options', 'Target', 'Rule Usage', 'Disabled', 'Description']
    elif policy_type == 'nat':
        fieldnames = ['Device-Group', 'Rule Type', 'Rule Name', 'Tags', 'Original Packet Source Zone', 'Original Packet Destination Zone', 'Original Packet Destination Interface', 'Original Packet Source Address', 'Original Packet Destination Address', 'Original Packet Service', 'Translated Packet Source Translation', 'Translated Packet Destination Translation', 'Target', 'Rule Usage', 'Disabled', 'Description']

    with open(file_name, 'w', newline='') as csvfile:
        writer = csv.DictWriter(csvfile, fieldnames=fieldnames)
        writer.writeheader()

        for device_group in device_groups:
            print(f"Processing Device Group: {device_group.name}")
            for rule_type in ['pre-rulebase', 'post-rulebase']:
                rules, disabled_statuses = fetch_rules(device_group, rule_type, policy_type, panorama)
                print(f"Found {len(rules)} {rule_type} {policy_type} rules for {device_group.name}")

                rule_usage_data = get_rule_usage(device_group, rule_type, policy_type, ssh)

                for rule in rules:
                    rule_usage = rule_usage_data.get(rule.name, '-')
                    print(f"Rule name: {rule.name}, Rule usage: {rule_usage}")

                    if policy_type == 'security':
                        writer.writerow({
                            'Device-Group': device_group.name,
                            'Rule Type': rule_type,
                            'Rule Name': rule.name,
                            'Tags': ','.join(rule.tag) if rule.tag else '',
                            'Source Zone': ','.join(rule.fromzone),
                            'Source Address': ','.join(rule.source),
                            'Source User': ','.join(rule.source_user),
                            'Source Devices': ','.join(rule.source_device),
                            'Destination Zone': ','.join(rule.tozone),
                            'Destination Address': ','.join(rule.destination),
                            'Destination Devices': ','.join(rule.destination_device),
                            'Application': ','.join(rule.application),
                            'Service': ','.join(rule.service),
                            'URL Category': ','.join(rule.category),
                            'Action': rule.action,
                            'Profile Group': rule.profile_setting,
                            'Options': rule.options,
                            'Target': ','.join(rule.target) if isinstance(rule.target, (list, tuple)) else rule.target,
                            'Rule Usage': rule_usage,
                            'Disabled': disabled_statuses[rule.name] if rule.name in disabled_statuses else False,
                            'Description': rule.description
                        })
                    elif policy_type == 'nat':
                        writer.writerow({
                            'Device-Group': device_group.name,
                            'Rule Type': rule_type,
                            'Rule Name': rule.name,
                            'Tags': ','.join(rule.tag) if rule.tag else '',
                            'Original Packet Source Zone': ','.join(rule.fromzone),
                            'Original Packet Destination Zone': ','.join(rule.tozone),
                            'Original Packet Destination Interface': rule.to_interface,
                            'Original Packet Source Address': ','.join(rule.source),
                            'Original Packet Destination Address': ','.join(rule.destination),
                            'Original Packet Service': rule.service,
                            'Translated Packet Source Translation': rule.source_translation_type,
                            'Translated Packet Destination Translation': rule.destination_translated_address,
                            'Target': ','.join(rule.target) if isinstance(rule.target, (list, tuple)) else rule.target,
                            'Rule Usage': rule_usage,
                            'Disabled': disabled_statuses[rule.name] if rule.name in disabled_statuses else False,
                            'Description': rule.description
                        })

def main():
    policy_type = input("Enter rule type (security/nat): ")
    assert policy_type in ['security', 'nat'], "Invalid rule type. Please enter 'security' or 'nat'."

    panorama = Panorama(PANORAMA_IP, USERNAME, PASSWORD)
    device_groups = DeviceGroup.refreshall(panorama)

    ssh = ConnectHandler(device_type='paloalto_panos', ip=PANORAMA_IP, username=USERNAME, password=PASSWORD)
    time.sleep(5)

    write_rules_to_csv(f'{policy_type}-rules.csv', device_groups, panorama, ssh, policy_type)

    ssh.disconnect()

if __name__ == "__main__":
    main()
