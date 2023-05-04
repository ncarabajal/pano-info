import csv
import re
from panos.panorama import Panorama, DeviceGroup
from panos.policies import PreRulebase, PostRulebase, SecurityRule
from netmiko import ConnectHandler, SSHDetect
import time
from lxml import etree

PANORAMA_IP = "IP-INFO"
USERNAME = "USERNAME"
PASSWORD = "PASSWORD"

def fetch_rules(device_group, rule_type, panorama):
    rulebase_class = PreRulebase if rule_type == 'pre-rulebase' else PostRulebase
    rulebase = rulebase_class()
    device_group.add(rulebase)
    rules = SecurityRule.refreshall(rulebase, add=True)

    # Fetch the complete rulebase XML for the current device group
    rulebase_tree = panorama.xapi.get(xpath=f"/config/devices/entry[@name='localhost.localdomain']/device-group/entry[@name='{device_group.name}']/{rule_type}/security")

    # Update the 'disabled' attribute of each rule in a separate dictionary
    disabled_statuses = {}
    for rule in rules:
        rule_xml = rulebase_tree.find(f".//entry[@name='{rule.name}']")
        if rule_xml is not None:
            disabled_element = rule_xml.find('./disabled')
            disabled_statuses[rule.name] = disabled_element is not None and disabled_element.text == 'yes'

    return rules, disabled_statuses

def get_rule_usage(device_group, rule_type, ssh):
    try:
        cmd = f"show rule-hit-count device-group {device_group.name} {rule_type} security rules all"
        response_text = ssh.send_command(cmd, expect_string=r'[>#]')

        # Adding a delay before processing the output
        time.sleep(5)

        print(f"Response text for {device_group.name} {rule_type}:")
        print(response_text)

        rule_usage_data = {}
        for line in response_text.strip().split("\n")[2:]:
            match = re.match(r"^(.+?)\s+(Used|Unused|Partially)\s", line)
            if match:
                rule_name, rule_usage = match.groups()
                rule_usage_data[rule_name] = rule_usage
            else:
                print(f"Error parsing line: {line}")

        return rule_usage_data
    except Exception as e:
        print(f"Error fetching rule usage data: {type(e).__name__}: {str(e)}")
        return {}

def write_rules_to_csv(file_name, device_groups, panorama, ssh):
    with open(file_name, 'w', newline='') as csvfile:
        fieldnames = [
            'Device-Group', 'Rule Type', 'Rule Name', 'Tags',
            'Source Zone', 'Source Address', 'Source User', 'Source Devices',
            'Destination Zone', 'Destination Address', 'Destination Devices',
            'Application', 'Service', 'URL Category', 'Action', 'Profile Group', 'Options',
            'Target', 'Rule Usage', 'Disabled', 'Description'
        ]
        writer = csv.DictWriter(csvfile, fieldnames=fieldnames)
        writer.writeheader()

        for device_group in device_groups:
            print(f"Processing Device Group: {device_group.name}")
            for rule_type in ['pre-rulebase', 'post-rulebase']:
                rules, disabled_statuses = fetch_rules(device_group, rule_type, panorama)
                print(f"Found {len(rules)} {rule_type} rules for {device_group.name}")

                rule_usage_data = get_rule_usage(device_group, rule_type, ssh)

                for rule in rules:
                    rule_usage = rule_usage_data.get(rule.name, '-')
                    print(f"Rule name: {rule.name}, Rule usage: {rule_usage}")
                    writer.writerow({
                        'Device-Group': device_group.name,
                        'Rule Type': rule_type,
                        'Rule Name': rule.name,
                        'Tags': ','.join(rule.tag) if rule.tag else '',
                        'Source Zone': ','.join(rule.fromzone),
                        'Source Address': ','.join(rule.source),
                        'Source User': ','.join(rule.source_user) if isinstance(rule.source_user, (list, tuple)) else '',
                        'Source Devices': ','.join(rule.source_devices) if hasattr(rule, 'source_devices') and isinstance(rule.source_devices, (list, tuple)) else '',
                        'Destination Zone': ','.join(rule.tozone),
                        'Destination Address': ','.join(rule.destination),
                        'Destination Devices': ','.join(rule.destination_devices) if hasattr(rule, 'destination_devices') and isinstance(rule.destination_devices, (list, tuple)) else '',
                        'Application': ','.join(rule.application),
                        'Service': ','.join(rule.service),
                        'URL Category': ','.join(rule.category) if rule.category else '',
                        'Action': rule.action,
                        'Profile Group': rule.group,
                        'Options': rule.log_setting,
                        'Target': ','.join(rule.target) if isinstance(rule.target, (list, tuple)) else rule.target,
                        'Rule Usage': rule_usage,
                        'Disabled': disabled_statuses[rule.name] if rule.name in disabled_statuses else False,
                        'Description': rule.description
                    })

def main():
    panorama = Panorama(PANORAMA_IP, USERNAME, PASSWORD)
    device_groups = DeviceGroup.refreshall(panorama)

    ssh = ConnectHandler(device_type='paloalto_panos', ip=PANORAMA_IP, username=USERNAME, password=PASSWORD)

    # Adding a 5-second delay after connecting to the device using SSH
    time.sleep(5)

    write_rules_to_csv('pre-post-panorama-security-rules.csv', device_groups, panorama, ssh)

    ssh.disconnect()

if __name__ == "__main__":
    main()
