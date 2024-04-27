import meraki
import json
import re


def configure_ports_choice():

    API_KEY = input("Please enter your API KEY: ")

    dashboard = meraki.DashboardAPI(API_KEY, suppress_logging=True)

    def get_org_id():
        try:
            response = dashboard.organizations.getOrganizations()
            print(f"Here are the Organizations that API key has permissions to:\n")
            sorted_orgs = sorted(response, key=lambda org: org['name'])  # Sort organizations alphabetically by name
            for org in sorted_orgs:
                print(f"{org['name']}-{org['id']}\n")
            return sorted_orgs  # Return the sorted list
        except meraki.APIError as e:
            print(f"Meraki API error: {e}")
            return None
        except Exception as e:
            print(f"Some other error occurred: {e}")
            return None
  

    org_id = get_org_id()


    orgselection = input("\nPlease enter the orgnization number you wish to configure: ")

    def get_network_names(orgselection):
        try:
            response = dashboard.organizations.getOrganizationNetworks(orgselection)
            sorted_networks = sorted(response, key=lambda net: net['name'])  # Sort networks alphabetically by name
            print(f"\nHere are the Networks within Organization {orgselection}:")
            for network in sorted_networks:
                print(network['name'], "-", network['id'])
            return sorted_networks  # Return the sorted list
        except meraki.APIError as e:
            print(f"Meraki API error: {e}")
            return None
        except Exception as e:
            print(f"Some other error occurred: {e}")
            return None



    network_names = get_network_names(orgselection)



    networkselection = input("\nPlease enter the network number you wish to configure: ")

    def get_switches(networkselection):
        try:
            response = dashboard.networks.getNetworkDevices(networkselection)
        except meraki.APIError as e:
            print(f"Meraki API error: {e}")
            return None
        except Exception as e:
            print(f"Some other error occurred: {e}")
            return None
        
        print(f"\nHere are the switch tag names in network {networkselection}:")
        seen_tags = set()  # Use a set to keep track of unique tags
        for device in response:
            if 'tags' in device and (device['model'].startswith('MS') or device['model'].startswith('C9')):
                for tag in device['tags']:
                    if tag:  # Check if tag is not empty
                        seen_tags.add(tag.strip())  # Use strip() to remove any leading/trailing whitespace

        # Print the tags separated by commas
        if seen_tags:
            print(", ".join(sorted(seen_tags)))  # Sort tags alphabetically and join them into a string
        else:
            print("No tags found.")

    switches = get_switches(networkselection)


    tagselection = input("\nPlease enter the switch tag you wish to configure: ")


    def get_tag_name(tagselection):
        try:
            response = dashboard.networks.getNetworkDevices(networkselection)
        except meraki.APIError as e:
            print(f"Meraki API error: {e}")
            return None
        except Exception as e:
            print(f"Some other error occurred: {e}")
            return None
        serial_list = []

        for device in response:
            # Check if the device's model starts with 'MS' or 'C9'
            if (device['model'].startswith('MS') or device['model'].startswith('C9')):
                # Check if the tagselection is in the device's tags list
                if tagselection in device.get('tags', []):
                    serial_list.append(device['serial'])

        return serial_list
    serial_list = get_tag_name(tagselection)
    serial_list_count = len(serial_list)
    print(f"\n\033[1m\033[3m\033[31mThe tag you have entered has matched to {serial_list_count} switches. Please double check this number equals the tag count in dashboard and is what you expect. Changes made via this program will impact all serial numbers assigned to this tag.\033[0m\n")

    def parse_range_to_numbers(portentry):
        # Split the input by commas to handle multiple entries
        entries = portentry.split(',')
        port_ids = []  # Initialize an empty list to store the port IDs

        # Adjusted regular expression pattern for modules (e.g., "1_MA-MOD-4X10G_1")
        module_pattern = re.compile(r'^(\d+_MA-MOD-\d+X\d+G_\d+)$')

        # Process each entry
        for entry in entries:
            entry = entry.strip()  # Remove any leading/trailing whitespace
            
            # Check if the entry matches the module pattern
            if module_pattern.match(entry):
                port_ids.append(entry)  # Append the module identifier to the list
                continue

            # If entry is a range (e.g., "7-8")
            if '-' in entry:
                try:
                    start, end = map(int, entry.split('-'))
                    port_ids.extend(range(start, end + 1))  # Extend the list with the range
                except ValueError:
                    print(f"Invalid range '{entry}'. Please enter a valid range like '1-24'.")
                continue

            # If entry is a single number (e.g., "7")
            try:
                port_id = int(entry)
                port_ids.append(port_id)  # Append the single port ID to the list
            except ValueError:
                print(f"Invalid port number '{entry}'. Please enter a valid number.")

        return port_ids

    
    portentry = input("Please enter a port number and/or range. Multiple values can be entered separated with a comma (e.g., '1-24' or '1-10, 12'). For modules, use the format '1_MA-MOD-4X10G_1'. Module ports will need to be entered one by one separated by a comma: ")
    port_ids = parse_range_to_numbers(portentry)


    def profile_id_Function(profile_Enabled):
        if profile_Enabled == "true":
            profile_id = input("\nEnter the profile ID. This can be obtained by running a GET call to a port already configured with the port profile. : ")
            return profile_id
        else:
            profile_id = ""
            return profile_id
    def profile_iname_Function(profile_Enabled):
        if profile_Enabled == "true":
            profile_iname = input("Enter the vlan profiles iname. This is for the vlan profiles feature. If not in use enter a blank value: ")
            return profile_iname
        else:
            profile_iname = ""
            return profile_iname
    def port_enabled_Function(profile_Enabled):
        if profile_Enabled == "true":
            return
        else:
            port_enabled = input("Port(s) enabled? Enter true or false: ")
            return port_enabled

    def vlan_Function(profile_Enabled):
        if profile_Enabled == "true":
            return
        if port_type == "access":
            vlan_function = input("Enter the data/access vlan number: ")
            return vlan_function
        else:
            port_type == "trunk"
            vlan_function = input("Enter the native (untagged) vlan number: ")
            return vlan_function
    def voice_Vlan_Function(profile_Enabled):
        if profile_Enabled == "true":
            return
        if port_type == "access":
            voice_Vlan = input("Enter the voice vlan number: ")
            return voice_Vlan
        else:
            voice_Vlan = ""
            return voice_Vlan
    def allowed_Vlans_Function(profile_Enabled):
        if profile_Enabled == "true":
            return
        if port_type == "trunk":
            allowed_Vlans_function = input("Enter the allowed vlan's for the trunk port(s). You can enter a range like 1-10, or multiple values separated by a comma i.e. 1-12, 14, or the word all to allow all vlans: ")
            return allowed_Vlans_function
        else:
            allowed_Vlans_function = ""
            return allowed_Vlans_function
    def mac_Allow_List_Function(profile_Enabled):
        if profile_Enabled == "true":
            return
        if access_policy == "MAC allow list":
            macs_allowed = input("Enter the MAC addresses for the allow list. Separate each mac address with a comma and a space: ")
            mac_Allow_List = [mac.strip() for mac in macs_allowed.split(',')]
            return mac_Allow_List
        else:
            mac_Allow_List = ""
            return mac_Allow_List
    def sticky_Mac_Allow_List_Function(profile_Enabled):
        if profile_Enabled == "true":
            return
        if access_policy == "Sticky MAC allow list":
            sticky_macs_allowed = input("Enter Sticky MAC's. Separate each mac address with a comma: ")
            sticky_Mac_Allow_List = [mac.strip() for mac in sticky_macs_allowed.split(',')]
            return sticky_Mac_Allow_List
        else:
            sticky_Mac_Allow_List = ""
            return sticky_Mac_Allow_List
    def sticky_Mac_Allow_List_Limit_Function(profile_Enabled):
        if profile_Enabled == "true":
            return
        if access_policy == "Sticky MAC allow list":
            sticky_Mac_Allow_List_Limit = input("Enter the sticky MAC allow limit: ")
            return sticky_Mac_Allow_List_Limit
        else:
            sticky_Mac_Allow_List_Limit = ""
            return sticky_Mac_Allow_List_Limit
    def access_policy_Function(profile_Enabled):
        if profile_Enabled == "true":
            return
        if port_type == "trunk":
            access_policy = input("Enter Open, MAC allow list, Sticky MAC allow list: ")
            return access_policy
        else:
            if port_type == "access":
                access_policy = input("Enter Open, Custom access policy, MAC allow list, Sticky MAC allow list: ")
                return access_policy
    def access_Policy_Number_Function(profile_enabled, access_policy):
        access_Policy_Number = ""
        if profile_enabled == "true":
            return access_Policy_Number
        
        if access_policy == "Custom access policy":
            access_Policy_Number = input("Enter the access policy group ID number. This depends on the position of the access policy in dashboard on switching>access policies page. If the first configuired access policy is wanted then enter 1 so on and so forth: ")
            return access_Policy_Number

    def poe_enabled_Function(profile_Enabled):
        if profile_Enabled == "true":
            return
        else:
            poe_enabled = input("Port PoE enabled? Enter true or false. Port PoE is turned on by default. If the switch does not support PoE enter no value here: ")
            return poe_enabled
    def port_type_Function(profile_Enabled):
        if profile_Enabled == "true":
            return
        else:
            port_type = input("Port type? Enter access or trunk *This configuration is required as what is entered here will dictate further configuration options*: ")
            return port_type
    def isolation_enabled_Function(profile_Enabled):
        if profile_Enabled == "true":
            return
        else:
            isolation_enabled = input("Is isolation enabled? Enter true or false. Default value is false: ")
            return isolation_enabled
    def rstp_Enabled_Function(profile_Enabled):
        if profile_Enabled == "true":
            return
        else:
            rstp_Enabled = input("RSTP enabled? Enter true or false: ")
            return rstp_Enabled
    def stp_Guard_Function(profile_Enabled):
        if profile_Enabled == "true":
            return
        else:
            stp_Guard = input("STP Guard feature? Enter disabled, root guard, bpdu guard, loop guard: ")
            return stp_Guard
    def link_negotiation_Function(profile_Enabled):
        if profile_Enabled == "true":
            return
        else:
            link_negotiation = input("Enter the link negotiation configuration. Possible values are Auto negotiate, 1 Gigabit full duplex (forced), 100 Megabit (auto), 100 Megabit half duplex (forced), 100 Megabit full duplex (forced), 10 Megabit (auto), 10 Megabit half duplex (forced), 10 Megabit full duplex (forced): ")
            return link_negotiation
    def port_Schedule_ID_Function(profile_Enabled):
        if profile_Enabled == "true":
            return
        else:
            port_Schedule_ID = input("Enter the port scheudle id. If no schedule enter None: ")
            return port_Schedule_ID
    def udld_Function(profile_Enabled):
        if profile_Enabled == "true":
            return
        else:
            udld = input("Enter UDLD configuration. Either Alert only or Enforce: ")
            return udld
    def dai_Trusted_Function(profile_Enabled):
        if profile_Enabled == "true":
            return
        else:
            dai_Trusted = input("DAI trusted port? Enter true or false: ")
            return dai_Trusted

    def adaptive_Policy_GroupId_Function(networkselection, tagselection, port_type, profile_Enabled):
        if profile_Enabled == "true":
            return

        try:
            response = dashboard.networks.getNetworkDevices(networkselection)
            all_devices_compatible = True  # Assume all devices are compatible initially
        except meraki.APIError as e:
            print(f"Meraki API error: {e}")
            return None
        except Exception as e:
            print(f"Some other error occurred: {e}")
            return None

        for device in response:
            # Check if device has tags and the tagselection is within those tags
            if 'tags' in device and tagselection in device['tags']:
                # Now check if the model starts with 'MS390' or 'C9'
                if not (device['model'].startswith('MS390') or device['model'].startswith('C9')):
                    all_devices_compatible = False
                    break  # No need to check further if one device is not compatible

        # Corrected the boolean comparison and the missing colon
        if all_devices_compatible:
            adaptive_Policy_GroupId = input("\nEnter the adaptive policy group ID number. The adaptive policy group ID that will be used to tag traffic through this switch port. This ID must pre-exist during the configuration, else it needs to be created using adaptivePolicy/groups API. Cannot be applied to a port bound to a port profile. *It is recommended to manually set a port in dashboard to the adaptive group # and then run a GET for the config of that port as this number is not the tag number you configured in dashboard but a unique string that dashboard applies in this field on the port config itself.*If adaptive policy is not enabled in the network leave this field blank: ")
        else:
            adaptive_Policy_GroupId = ""

        return adaptive_Policy_GroupId
       
    #If the switch does not support Peer SGT entering any value will cause the API to fail with a 400 error. This has not been tested on 390's or catalyst.
    # https://documentation.meraki.com/General_Administration/Cross-Platform_Content/Adaptive_Policy_MS_Configuration_Guide
    def peer_Sgt_Capable_Function(networkselection, tagselection, port_type, profile_Enabled):
        if profile_Enabled == "true":
            return
        try:
            response = dashboard.networks.getNetworkDevices(networkselection)
            all_devices_compatible = True  # Assume all devices are compatible initially
        except meraki.APIError as e:
            print(f"Meraki API error: {e}")
            return None
        except Exception as e:
            print(f"Some other error occurred: {e}")
            return None


        for device in response:
            # Check if device has tags and the tagselection is within those tags
            if 'tags' in device and tagselection in device['tags']:
                # Now check if the model ends with '390' or starts with 'C9'
                if not (device['model'].startswith('MS390') or device['model'].startswith('C9')):
                    all_devices_compatible = False
                    break  # No need to check further if one device is not compatible
        # Only proceed if all devices are compatible and the conditions are met
        if all_devices_compatible and port_type == "trunk":
            peer_Sgt_Capable = input("Enable peer sgt (security group tag)? Enter true or false. If true, Peer SGT is enabled for traffic through this switch port. Applicable to trunk ports only, not access ports. Cannot be applied to a port on a switch bound to profile. This feature is only supported on MS390's and Catalyst Switches. If adaptive policy is not enabled in the network leave this field blank: ")
        else:
            peer_Sgt_Capable = ""

        return peer_Sgt_Capable




    print("\n""\033[1m\033[31mIt is recommended to copy and paste exact values from the terminal prompts for configuration values to avoid errors, where applicable. If you do not want to include a configuration in your paramters within the API call and leave that configuration unchanged simply click enter with a blank value.\033[0m""\n")
    profile_Enabled = input("Configure a port profile? true or false. Configuring a port profile will skip all other configuration options as these configurations are tied to the port profile itself: ")
    profile_id = profile_id_Function(profile_Enabled)
    profile_iname = profile_iname_Function(profile_Enabled)
    port_enabled = port_enabled_Function(profile_Enabled)
    poe_enabled = poe_enabled_Function(profile_Enabled)
    port_type = port_type_Function(profile_Enabled)
    vlan = vlan_Function(profile_Enabled)
    voice_Vlan = voice_Vlan_Function(profile_Enabled)
    allowed_vlans = allowed_Vlans_Function(profile_Enabled)
    isolation_enabled = isolation_enabled_Function(profile_Enabled)
    rstp_Enabled = rstp_Enabled_Function(profile_Enabled)
    stp_Guard = stp_Guard_Function(profile_Enabled)
    link_negotiation = link_negotiation_Function(profile_Enabled)
    port_Schedule_ID = port_Schedule_ID_Function(profile_Enabled)
    udld = udld_Function(profile_Enabled) 
    access_policy = access_policy_Function(profile_Enabled)
    access_Policy_Number = access_Policy_Number_Function(profile_Enabled,access_policy)
    mac_Allow_List = mac_Allow_List_Function(profile_Enabled)
    sticky_Mac_Allow_List = sticky_Mac_Allow_List_Function(profile_Enabled)
    sticky_Mac_Allow_List_Limit = sticky_Mac_Allow_List_Limit_Function(profile_Enabled)
    #Storm control not supported at this time. Whatever configuration is there will remain unchanged. storm_Control_Enabled = input("Storm control enabled? Enter true or false: ")
    dai_Trusted = dai_Trusted_Function(profile_Enabled)
    peer_Sgt_Capable = peer_Sgt_Capable_Function(networkselection,tagselection,port_type,profile_Enabled)
    adaptive_Policy_GroupId = adaptive_Policy_GroupId_Function(networkselection,tagselection,port_type,profile_Enabled)



    def configure_ports(serial_list, port_ids):
        for serial in serial_list:
            for port in port_ids:
                # Create a dictionary with all parameters
                kwargs = {
                    'enabled': port_enabled if port_enabled != "" else None,
                    'poeEnabled': poe_enabled if poe_enabled != "" else None,
                    'type': port_type if port_type != "" else None,
                    'vlan': vlan if vlan != "" else None,
                    'voiceVlan': voice_Vlan if voice_Vlan != "" else None,
                    'allowedVlans': allowed_vlans if allowed_vlans != "" else None,
                    'isolationEnabled': isolation_enabled if isolation_enabled != "" else None,
                    'rstpEnabled': rstp_Enabled if rstp_Enabled != "" else None,
                    'stpGuard': stp_Guard if stp_Guard != "" else None,
                    'linkNegotiation': link_negotiation if link_negotiation != "" else None,
                    'portScheduleID': port_Schedule_ID if port_Schedule_ID != "" else None,
                    'udld': udld if udld != "" else None,
                    'accessPolicyType': access_policy if access_policy != "" else None,
                    'accessPolicyNumber': access_Policy_Number if access_Policy_Number != "" else None,
                    'macAllowList': mac_Allow_List if mac_Allow_List != "" else None,
                    'stickyMacAllowList': sticky_Mac_Allow_List if sticky_Mac_Allow_List != "" else None,
                    'stickyMacAllowListLimit': sticky_Mac_Allow_List_Limit if sticky_Mac_Allow_List_Limit != "" else None,
                    'adaptivePolicyGroupId': adaptive_Policy_GroupId if adaptive_Policy_GroupId != "" else None,
                    'peerSgtCapable': peer_Sgt_Capable if peer_Sgt_Capable != "" else None,
                    'daiTrusted': dai_Trusted if dai_Trusted != "" else None,
                    'profile': {
                        "enabled": profile_Enabled if profile_Enabled != "" else None,
                        "id": profile_id if profile_id != "" else None,
                        "iname": profile_iname if profile_iname != "" else None
                    } if profile_Enabled != "" else None,
                    # Add other parameters as needed
                }
                # Remove keys where the value is None
                kwargs = {k: v for k, v in kwargs.items() if v is not None}
                #print(kwargs)
                try:
                    response = dashboard.switch.updateDeviceSwitchPort(serial, port, **kwargs)
                    print(f"\033[1m\033[3m\033[32mSuccessfully\033[0m configured port {port} on serial {serial}.")
                except Exception as e:  # Catch any exception and print an error message
                    print(f"\033[1m\033[3m\033[31mError\033[0m configuring port {port} on serial {serial}: {e}")
                    return  # Exit the function after an error

        # If the loop completes successfully
        print("All ports have been successfully configured.")

    # Call the function with the serial numbers and port IDs
    configure_ports(serial_list, port_ids)

def configure_link_aggregation_choice():

    API_KEY = input("Please enter your API KEY: ")

    dashboard = meraki.DashboardAPI(API_KEY, suppress_logging=True)

    def get_org_id():
        try:
            response = dashboard.organizations.getOrganizations()
            print(f"Here are the Organizations that API key has permissions to:\n")
            sorted_orgs = sorted(response, key=lambda org: org['name'])  # Sort organizations alphabetically by name
            for org in sorted_orgs:
                print(f"{org['name']}-{org['id']}\n")
            return sorted_orgs  # Return the sorted list
        except meraki.APIError as e:
            print(f"Meraki API error: {e}")
            return None
        except Exception as e:
            print(f"Some other error occurred: {e}")
            return None
  

    org_id = get_org_id()


    orgselection = input("\nPlease enter the orgnization number you wish to configure: ")

    def get_network_names(orgselection):
        try:
            response = dashboard.organizations.getOrganizationNetworks(orgselection)
            sorted_networks = sorted(response, key=lambda net: net['name'])  # Sort networks alphabetically by name
            print(f"\nHere are the Networks within Organization {orgselection}:")
            for network in sorted_networks:
                print(network['name'], "-", network['id'])
            return sorted_networks  # Return the sorted list
        except meraki.APIError as e:
            print(f"Meraki API error: {e}")
            return None
        except Exception as e:
            print(f"Some other error occurred: {e}")
            return None



    network_names = get_network_names(orgselection)



    networkId = input("\nPlease enter the network number you wish to configure: ")

    def get_switches(networkId):
        try:
            response = dashboard.networks.getNetworkDevices(networkId)
        except meraki.APIError as e:
            print(f"Meraki API error: {e}")
            return None
        except Exception as e:
            print(f"Some other error occurred: {e}")
            return None
        
        print(f"\nHere are the switch tag names in network {networkId}:")
        seen_tags = set()  # Use a set to keep track of unique tags
        for device in response:
            if 'tags' in device and (device['model'].startswith('MS') or device['model'].startswith('C9')):
                for tag in device['tags']:
                    if tag:  # Check if tag is not empty
                        seen_tags.add(tag.strip())  # Use strip() to remove any leading/trailing whitespace

        # Print the tags separated by commas
        if seen_tags:
            print(", ".join(sorted(seen_tags)))  # Sort tags alphabetically and join them into a string
        else:
            print("No tags found.")

    switches = get_switches(networkId)


    tagselection = input("\nPlease enter the switch tag you wish to configure: ")


    def get_tag_name(tagselection):
        try:
            response = dashboard.networks.getNetworkDevices(networkId)
        except meraki.APIError as e:
            print(f"Meraki API error: {e}")
            return None
        except Exception as e:
            print(f"Some other error occurred: {e}")
            return None
        serial_list = []

        for device in response:
            # Check if the device's model starts with 'MS' or 'C9'
            if (device['model'].startswith('MS') or device['model'].startswith('C9')):
                # Check if the tagselection is in the device's tags list
                if tagselection in device.get('tags', []):
                    serial_list.append(device['serial'])

        return serial_list
    serial_list = get_tag_name(tagselection)
    serial_list_count = len(serial_list)
    print(f"\n\033[1m\033[3m\033[31mThe tag you have entered has matched to {serial_list_count} switches. Please double check this number equals the tag count in dashboard and is what you expect. Changes made via this program will impact all serial numbers assigned to this tag.\033[0m\n")

    def parse_range_to_numbers(portentry):
        # Split the input by commas to handle multiple entries
        entries = portentry.split(',')
        port_ids = []  # Initialize an empty list to store the port IDs

        # Adjusted regular expression pattern for modules (e.g., "1_MA-MOD-4X10G_1")
        module_pattern = re.compile(r'^(\d+_MA-MOD-\d+X\d+G_\d+)$')

        # Process each entry
        for entry in entries:
            entry = entry.strip()  # Remove any leading/trailing whitespace
            
            # Check if the entry matches the module pattern
            if module_pattern.match(entry):
                port_ids.append(entry)  # Append the module identifier to the list
                continue

            # If entry is a range (e.g., "7-8")
            if '-' in entry:
                try:
                    start, end = map(int, entry.split('-'))
                    port_ids.extend(range(start, end + 1))  # Extend the list with the range
                except ValueError:
                    print(f"Invalid range '{entry}'. Please enter a valid range like '1-24'.")
                continue

            # If entry is a single number (e.g., "7")
            try:
                port_id = int(entry)
                port_ids.append(port_id)  # Append the single port ID to the list
            except ValueError:
                print(f"Invalid port number '{entry}'. Please enter a valid number.")

        return port_ids
    
    portentry = input("Please enter a port number and/or range. Multiple values can be entered separated with a comma (e.g., '1-24' or '1-10, 12'). For modules, use the format '1_MA-MOD-4X10G_1'. Module ports will need to be entered one by one separated by a comma: ")
    port_ids = parse_range_to_numbers(portentry)


    def configure_link_aggregation_Function(networkId, serial_list, port_ids):
        for serial in serial_list:
            # Construct the payload for this serial number with all the port IDs
            switch_ports = [{"serial": serial, "portId": str(port)} for port in port_ids]
            payload = {"switchPorts": switch_ports}

            print(f"Calling createNetworkSwitchLinkAggregation with networkId={networkId} and payload={payload}")

            try:
                # The API call to create a link aggregation
                # Pass networkId and payload as named arguments
                response = dashboard.switch.createNetworkSwitchLinkAggregation(networkId=networkId, switchPorts=payload['switchPorts'])
                print(f"\033[1m\033[3m\033[32mSuccessfully\033[0m configured link aggregation for the following configuration: {payload}. Response: {response}")
            except Exception as e:
                print(f"\033[1m\033[3m\033[31mError\033[0m configuring link aggregation with the following configuration: {payload}. Error: {e}")


    configure_link_aggregation_Function(networkId, serial_list, port_ids)


def main():
    while True:
        # Ask the user for the type of configuration they would like to perform
        config_selection = input("Enter 'ports' to configure ports, 'link-aggregation' to configure link aggregation, or 'exit' to exit the program: ").strip().lower()

        if config_selection == 'ports':
            configure_ports_choice()
        elif config_selection == 'link-aggregation':
            configure_link_aggregation_choice()
        elif config_selection == 'exit':
            print("Exiting the program.")
            break  # Break out of the loop to exit the program
        else:
            print("Invalid selection. Please enter 'ports' or 'link-aggregation'.")

if __name__ == "__main__":
    main()