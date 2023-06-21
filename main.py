import csv
import re
from panos.panorama import Panorama, DeviceGroup
from panos.policies import PreRulebase, PostRulebase, SecurityRule, NatRule
from panos import errors
from netmiko import ConnectHandler, SSHDetect
import time

PANORAMA_IP = "IP"
USERNAME = "username"
PASSWORD = "password"

def fetch_rules(device_group, rule_type, policy_type, panorama, ssh):  # add ssh here
    rulebase_class = PreRulebase if rule_type == 'pre-rulebase' else PostRulebase
    rulebase = rulebase_class()
    device_group.add(rulebase)
    rules = SecurityRule.refreshall(rulebase, add=True) if policy_type == 'security' else NatRule.refreshall(rulebase, add=True)
    
    rule_usage_data = get_rule_usage(device_group, rule_type, policy_type, ssh)
    
    for rule in rules:
        rule_usage = rule_usage_data.get(rule.name, '-')
        if rule_usage == 'Unused':
            try:
                rule.tag.append('unused-3')
                rule.apply()
            except errors.PanDeviceXapiError as e:
                if "is already in use" in str(e):
                    # tag already in use, skipping
                    pass
                else:
                    # some other error occurred, raise it
                    raise

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
        fieldnames = ['Device-Group', 'Rule Type', 'Rule Name', 'Tags', 'Original Packet Source Zone', 'Original Packet Destination Zone', 'Original Packet Destination Interface', 'Original Packet Source Address', 'Original Packet Destination Address', 'Original Packet Service', 'Translated Packet Source Translation', 'Translated Packet Destination Translation', 'Bi-directional', 'Translated Packet Destination Service', 'Target', 'Rule Usage', 'Disabled', 'Description', 'Source Translation Type', 'Source Translation Address Type', 'Source Translation Interface', 'Source Translation IP Address', 'Source Translation Translated Addresses', 'Source Translation Fallback Type', 'Source Translation Fallback Translated Addresses', 'Source Translation Fallback Interface', 'Source Translation Fallback IP Type', 'Source Translation Fallback IP Address', 'Source Translation Static Translated Address', 'Source Translation Static Bi-directional']

    with open(file_name, 'w', newline='') as csvfile:
        writer = csv.DictWriter(csvfile, fieldnames=fieldnames)
        writer.writeheader()

        for device_group in device_groups:
            print(f"Processing Device Group: {device_group.name}")
            for rule_type in ['pre-rulebase', 'post-rulebase']:
                rules, disabled_statuses = fetch_rules(device_group, rule_type, policy_type, panorama, ssh)

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
                            'Rule Usage': rule_usage
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
                            'Bi-directional':rule.source_translation_static_bi_directional,
                            'Translated Packet Destination Service': rule.service,
                            'Target': ','.join(rule.target) if isinstance(rule.target, (list, tuple)) else rule.target,
                            'Rule Usage': rule_usage,
                            'Disabled': disabled_statuses[rule.name] if rule.name in disabled_statuses else False,
                            'Description': rule.description,
                            'Source Translation Type': rule.source_translation_type,
                            'Source Translation Address Type': rule.source_translation_address_type,
                            'Source Translation Interface': rule.source_translation_interface,
                            'Source Translation IP Address': rule.source_translation_ip_address,
                            'Source Translation Translated Addresses': ','.join(rule.source_translation_translated_addresses) if isinstance(rule.source_translation_translated_addresses, (list, tuple)) else rule.source_translation_translated_addresses,
                            'Source Translation Fallback Type': rule.source_translation_fallback_type,
                            'Source Translation Fallback Translated Addresses': ','.join(rule.source_translation_fallback_translated_addresses) if isinstance(rule.source_translation_fallback_translated_addresses, (list, tuple)) else rule.source_translation_fallback_translated_addresses,
                            'Source Translation Fallback Interface': rule.source_translation_fallback_interface,
                            'Source Translation Fallback IP Type': rule.source_translation_fallback_ip_type,
                            'Source Translation Fallback IP Address': rule.source_translation_fallback_ip_address,
                            'Source Translation Static Bi-directional': rule.source_translation_static_bi_directional
                        })

def commit_changes(panorama):
    """
    Commits changes made to the panorama configuration
    """
    panorama.commit(sync=True, sync_all=True, admin='my_admin_name')  # Add your admin username in admin

def main():
    policy_type = input("Enter rule type (security/nat): ")
    assert policy_type in ['security', 'nat'], "Invalid rule type. Please enter 'security' or 'nat'."

    panorama = Panorama(PANORAMA_IP, USERNAME, PASSWORD)
    device_groups = DeviceGroup.refreshall(panorama)

    ssh = ConnectHandler(device_type='paloalto_panos', ip=PANORAMA_IP, username=USERNAME, password=PASSWORD)
    time.sleep(5)

    write_rules_to_csv(f'{policy_type}-rules.csv', device_groups, panorama, ssh, policy_type)

    ssh.disconnect()
    commit_changes(panorama)  # It will now commit only your changes

if __name__ == "__main__":
    main()

