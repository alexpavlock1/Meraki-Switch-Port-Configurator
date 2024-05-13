import batch_helper
import meraki
import json
import re



def configure_ports_choice():

    API_KEY = input("Please enter your API Key: ").strip()

    dashboard = meraki.DashboardAPI(API_KEY, suppress_logging=True)

    def get_org_id():
        while True:
            try:
                response = dashboard.organizations.getOrganizations()
                if not response:
                    print("\033[1m\033[3m\033[31mNo organizations found with the provided API key. Please ensure your API key is correct and try again.\033[0m\n")
                    return None

                valid_org_ids = {org['id'] for org in response}
                print(f"Here are the organizations that the API key has permissions to:\n")
                for org in response:
                    print(f"{org['name']} - {org['id']}")

                org_id = input("\nPlease enter the organization number you wish to configure: ").strip()
                if org_id in valid_org_ids:
                    return org_id
                else:
                    print("\033[1m\033[3m\033[31mThe entry did not match any of the organization IDs tied to that API key. Please try again.\033[0m\n")

            except meraki.APIError as e:
                if 400 <= e.status <= 499:
                    print(f"Client error occurred: {e.status} {e.reason}")
                    if e.status == 401:
                        print("\033[1m\033[3m\033[31mInvalid API key. Please ensure your API key is correct and try again.\033[0m\n")
                    return None
                else:
                    print(f"\033[1m\033[3m\033[31mMeraki API error:\033[0m\n {e}")
                    return None
            except Exception as e:
                print(f"\033[1m\033[3m\033[31mSome other error occurred:\033[0m\n {e}")
                return None

    # Loop to handle re-entry of the API key and fetching the organization ID
    while True:
        orgselection = get_org_id()
        if orgselection is None:
            # Prompt the user to enter the API key again
            api_key = input("Please enter your API Key: ").strip()
            dashboard = meraki.DashboardAPI(api_key=api_key, suppress_logging=True)
        else:
            break  # Valid organization ID was entered, exit the loop

    def get_network_names(orgselection):
        try:
            response = dashboard.organizations.getOrganizationNetworks(orgselection)
            sorted_networks = sorted(response, key=lambda net: net['name'])  # Sort networks alphabetically by name
            print(f"\nHere are the networks within Organization {orgselection}:")
            for network in sorted_networks:
                print(network['name'], "-", network['id'])
            return sorted_networks  # Return the sorted list
        except meraki.APIError as e:
            print(f"Meraki API error: {e}")
            return None
        except Exception as e:
            print(f"\033[1m\033[3m\033[31mSome other error occurred:\033[0m\n {e}")
            return None

    # Get the list of networks for the selected organization
    network_names = get_network_names(orgselection)

    if network_names is None:
        print("\033[1m\033[3m\033[31mAn error occurred while retrieving the network names.\033[0m\n")
    else:
        # Extract valid network IDs for checking user input
        valid_network_ids = {network['id'] for network in network_names}

        # Loop to prompt the user for a valid network ID
        while True:
            networkselection = input("\nPlease enter the network number you wish to configure: ").strip()
            if networkselection in valid_network_ids:
                break  # The user entered a valid network ID
            else:
                print("\033[1m\033[3m\033[31mThe network number you entered is not valid for the selected organization. Please try again.\033[0m\n")

    def get_tags(networkselection):
        try:
            response = dashboard.networks.getNetworkDevices(networkselection)
        except meraki.APIError as e:
            print(f"\033[1m\033[3m\033[31mMeraki API error:\033[0m\n {e}")
            return set()  # Return an empty set on error
        except Exception as e:
            print(f"\033[1m\033[3m\033[31mSome other error occurred:\033[0m\n {e}")
            return set()  # Return an empty set on error

        seen_tags = set()  # Use a set to keep track of unique tags
        for device in response:
            if 'tags' in device and device.get('tags') and (device['model'].startswith('MS') or device['model'].startswith('C9')):
                device_tags = device['tags']
                for tag in device_tags:
                    if tag:  # Check if tag is not empty
                        seen_tags.add(tag.strip())  # Use strip() to remove any leading/trailing whitespace

        if not seen_tags:
            print("\033[1m\033[3m\033[31mNo tags found attached to any switches in the selected network. Please create and attach a tag to the switches you wish to configure with this program. You can reference this KB article on guidance with tags: https://documentation.meraki.com/MS/Monitoring_and_Reporting/Using_Tags_to_Manage_Switches\033[0m\n")
            return None  # Exit the function as there are no tags to proceed with

        # Print the tags separated by commas
        print(", ".join(sorted(seen_tags)))  # Sort tags alphabetically and join them into a string
        return seen_tags

    # Code to get the network selection and call the get_tags function
    # networkselection = 'your_network_id_here'
    seen_tags = get_tags(networkselection)

    # If there are no tags, exit the function
    if seen_tags is None:
        exit(0)

    def tag_selection_function(seen_tags):
        while True:
            tagselection = input("\nPlease enter the switch tag you wish to configure: ").strip()
            if tagselection in seen_tags:
                return tagselection
            else:
                print(f"\033[1m\033[3m\033[31mInvalid input. You entered a tag name that is not assigned to any switches in the network you selected. Please enter one of the tag names:\033[0m\n {', '.join(sorted(seen_tags))}")

    # Call the tag_selection_function with the seen_tags
    tagselection = tag_selection_function(seen_tags)
    def get_tag_name(tagselection):
        try:
            response = dashboard.networks.getNetworkDevices(networkselection)
        except meraki.APIError as e:
            print(f"\033[1m\033[3m\033[31mMeraki API error:\033[0m\n {e}")
            return None
        except Exception as e:
            print(f"\033[1m\033[3m\033[31mSome other error occurred:\033[0m\n {e}")
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
    print(f"\033[1m\033[3m\033[33mThe tag you have entered has matched to {serial_list_count} switches. Please double check this number equals the tag count in dashboard and is what you expect. Changes made via this program will impact all serial numbers assigned to this tag.\033[0m\n")

    def parse_range_to_numbers(portentry):
        entries = portentry.split(',')
        port_ids = []  # Initialize an empty list to store the port IDs
        module_pattern = re.compile(r'^(\d+_MA-MOD-\d+X\d+G_\d+)$')

        for entry in entries:
            entry = entry.strip()
            
            if module_pattern.match(entry):
                port_ids.append(entry)
                continue
            
            if '-' in entry:
                try:
                    start, end = map(int, entry.split('-'))
                    port_ids.extend(range(min(start, end), max(start, end) + 1))
                except ValueError:
                    raise ValueError(f"Invalid range '{entry}'. Please enter a valid range like '1-24'.")
                continue
            
            try:
                port_id = int(entry)
                port_ids.append(port_id)
            except ValueError:
                raise ValueError(f"Invalid port number '{entry}'. Please enter a valid number.")
        
        # Check for duplicates by converting the list to a set and comparing sizes
        if len(port_ids) != len(set(port_ids)):
            raise ValueError("Duplicate port numbers found. Please enter unique port numbers or ranges without overlap.")
        
        return sorted(set(port_ids))  # Return a sorted list of unique port IDs

        # Loop to prompt the user for input until valid, non-duplicate ports are entered
    while True:
        try:
            portentry = input("Please enter a port number and/or range. Multiple values can be entered separated with a comma (e.g., '1-24' or '24-1, 12'). For modules, use the format '1_MA-MOD-4X10G_1'. Module ports will need to be entered one by one separated by a comma: ")
            port_ids = parse_range_to_numbers(portentry)
            break  # Exit loop if parsing is successful and no exceptions are raised
        except ValueError as e:
            print(f"\033[1m\033[3m\033[31m{e}\033[0m\n")

    def profile_Enabled_Function():
        valid_inputs = ["true", "false"]
        while True:
            profile_Enabled = input("Configure a port profile? true or false. Configuring a port profile will skip all other configuration options as these configurations are tied to the port profile itself. *This configuration is required as what is entered here will dictate further configuration options*: ").strip().lower()
            if profile_Enabled in valid_inputs:
                return profile_Enabled
            else:
                print("\033[1m\033[3m\033[31mInvalid input. Please enter 'true' or 'false'.\033[0m\n")
    def profile_id_Function(profile_Enabled):
        if profile_Enabled == "true":
            profile_id = input("\nEnter the port profile ID. This can be obtained by running a GET call to a port already configured with the port profile: ").strip()
            return profile_id
        else:
            profile_id = ""
            return profile_id
    def profile_iname_Function(profile_Enabled):
        if profile_Enabled == "true":
            profile_iname = input("Enter the vlan profiles iname. This is for the VLAN profiles feature. If not in use enter a blank value: ").strip()
            return profile_iname
        else:
            profile_iname = ""
            return profile_iname
    def port_enabled_Function(profile_Enabled):
        if profile_Enabled == "true":
            return
        while True:  # Keep asking until a valid input is provided
            port_enabled = input("Port(s) enabled? Enter true or false: ").strip().lower()
            # Check if the input is one of the accepted values or blank
            if port_enabled in ('true', 'false', ''):
                return port_enabled if port_enabled else None  # Return the input or None if blank
            else:
                print("\033[1m\033[3m\033[31mInvalid input. Please enter 'true', 'false', or leave blank.\033[0m\n")
    def poe_enabled_Function(profile_Enabled):
        if profile_Enabled == "true":
            return None
        # Define the valid inputs
        valid_inputs = ["true", "false", ""]
        while True: 
            poe_enabled = input("Port PoE enabled? Enter 'true' or 'false'. Port PoE is turned on by default. If the switch does not support PoE, enter no value here (leave blank to skip): ").strip().lower()
            if poe_enabled in valid_inputs:
                return poe_enabled
            else:
                print("\033[1m\033[3m\033[31mInvalid input. Please enter 'true', 'false', or leave blank to skip.\033[0m\n")
    def port_type_Function(profile_Enabled):
        if profile_Enabled == "true":
            return
        valid_inputs = ["access", "trunk"]
        while True:
            port_type = input("Port type? Enter access or trunk *This configuration is required as what is entered here will dictate further configuration options*: ").strip().lower()
            if port_type in valid_inputs:
                return port_type
            else:
                print("\033[1m\033[3m\033[31mInvalid input. Please enter 'access' or 'trunk'.\033[0m\n")
    def vlan_Function(profile_Enabled, port_type):
        if profile_Enabled == "true":
            return
        # Helper function to validate VLAN number
        def is_valid_vlan(vlan):
            try:
                return 1 <= int(vlan) <= 4094
            except ValueError:
                return False  # Non-integer value entered

        # Helper function to validate VLAN range
        def is_valid_vlan_range(vlan_range):
            match = re.match(r'^(\d+)-(\d+)$', vlan_range)
            if match:
                start, end = map(int, match.groups())
                return 1 <= start <= end <= 4094
            return False

        while True:  # Keep asking until a valid input is provided
            if port_type == "access":
                vlan_function = input("Enter the data/access VLAN number (1-4094): ").strip()
                if is_valid_vlan(vlan_function):
                    return vlan_function
            elif port_type == "trunk":
                vlan_function = input("Enter the native (untagged) VLAN number or range (e.g., 1-10) between 1-4094: ").strip()
                if is_valid_vlan(vlan_function) or is_valid_vlan_range(vlan_function):
                    return vlan_function
            # If the input is not valid, print an error message and ask again
            print("\033[1m\033[3m\033[31mInvalid input. Please enter a VLAN number or range between 1-4094 or leave blank.\033[0m\n")
    def voice_Vlan_Function(profile_Enabled, port_type):
        # Skip the function if profile is enabled or port type is not 'access'
        if profile_Enabled == "true" or port_type != "access":
            return
        # Function to check if the VLAN is valid
        def is_valid_vlan(vlan):
            try:
                return 1 <= int(vlan) <= 4094
            except ValueError:
                return False  # Non-integer value entered
        while True:  # Keep asking until a valid input is provided
            voice_vlan = input("Enter the voice VLAN number (1-4094): ").strip()
            if is_valid_vlan(voice_vlan):
                return voice_vlan
            else:
                print("\033[1m\033[3m\033[31mInvalid input. Please enter a valid VLAN number between 1-4094 or leave blank.\033[0m\n")
    def allowed_Vlans_Function(profile_Enabled, port_type):
        if profile_Enabled == "true" or port_type == "access":
            return
        # Helper function to validate VLAN number
        def is_valid_vlan(vlan):
            try:
                return 1 <= int(vlan) <= 4094
            except ValueError:
                return False  # Non-integer value entered
        # Helper function to validate VLAN range
        def is_valid_vlan_range(vlan_range):
            match = re.match(r'^(\d+)-(\d+)$', vlan_range)
            if match:
                start, end = map(int, match.groups())
                return 1 <= start <= end <= 4094
            return False
        while True:  # Keep asking until a valid input is provided
            allowed_Vlans_function = input("Enter the allowed VLANs for trunk port (e.g., 1,2-10,20) between 1-4094: ").strip()
            if allowed_Vlans_function == "":
                return
            # Split the input by commas and check each part
            vlan_parts = allowed_Vlans_function.split(',')
            if all(is_valid_vlan(vlan_part.strip()) or is_valid_vlan_range(vlan_part.strip()) for vlan_part in vlan_parts):
                return allowed_Vlans_function
            # If the input is not valid, print an error message and ask again
            print("\033[1m\033[3m\033[31mInvalid input. Please enter valid VLAN numbers or ranges between 1-4094, or leave blank to skip.\033[0m\n")
    def access_policy_Function(profile_Enabled, port_type):
        if profile_Enabled == "true":
            return None  # Return None if the profile is enabled

        # Define the valid inputs based on port_type
        valid_inputs_trunk = ["Open", "MAC allow list", "Sticky MAC allow list"]
        valid_inputs_access = ["Open", "Custom access policy", "MAC allow list", "Sticky MAC allow list"]

        # Use appropriate valid inputs based on port_type
        valid_inputs = valid_inputs_trunk if port_type == "trunk" else valid_inputs_access if port_type == "access" else None
         # Prompt the user until a valid input or blank entry is provided
        prompt_message = "Enter " + ", ".join(valid_inputs) + ": "
        while True:
            access_policy = input(prompt_message).strip()
            
            # Check for a blank entry or if the input is in the list of valid inputs
            if access_policy == "" or access_policy in valid_inputs:
                return access_policy
            else:
                print("\033[1m\033[3m\033[31mInvalid input. Please enter one of the allowed policies exactly as shown including punctuation, or leave blank to skip.\033[0m\n")
    def mac_Allow_List_Function(profile_Enabled,access_policy):
        if profile_Enabled == "true":
            return
        if access_policy == "MAC allow list":
            macs_allowed = input("Enter the MAC addresses for the allow list. Separate each mac address with a comma and a space. Format should look as the following - AA:AA:AA:AA:AA:AA: ")
            mac_Allow_List = [mac.strip() for mac in macs_allowed.split(',')]
            return mac_Allow_List
        else:
            mac_Allow_List = ""
            return mac_Allow_List
    def sticky_Mac_Allow_List_Function(profile_Enabled,access_policy):
        if profile_Enabled == "true":
            return
        if access_policy == "Sticky MAC allow list":
            sticky_macs_allowed = input("Enter Sticky MAC's. Separate each mac address with a comma. Format should look as the following - AA:AA:AA:AA:AA:AA: ")
            sticky_Mac_Allow_List = [mac.strip() for mac in sticky_macs_allowed.split(',')]
            return sticky_Mac_Allow_List
        else:
            sticky_Mac_Allow_List = ""
            return sticky_Mac_Allow_List
    def sticky_Mac_Allow_List_Limit_Function(profile_Enabled, access_policy):
        if profile_Enabled == "true":
            return ""
        if access_policy == "Sticky MAC allow list":
            while True:  # Keep asking until a valid input is provided
                sticky_Mac_Allow_List_Limit = input("Enter the sticky MAC allow limit (1-20): ").strip()
                # Check if the input is a digit and within the range 1 to 20
                if sticky_Mac_Allow_List_Limit.isdigit() and 1 <= int(sticky_Mac_Allow_List_Limit) <= 20:
                    return sticky_Mac_Allow_List_Limit
                else:
                    print("\033[1m\033[3m\033[31mInvalid input. Dashboard only allows for a number between 1 and 20. Please enter a number between 1 and 20.\033[0m\n")
        else:
            sticky_Mac_Allow_List_Limit = ""
            return sticky_Mac_Allow_List_Limit
    def access_Policy_Number_Function(profile_enabled, access_policy):
        if profile_enabled == "true":
            return
        if access_policy == "Custom access policy":
            while True:  # Keep asking until a valid input is provided
                access_Policy_Number = input("Enter the access policy group ID number (1-8). This depends on the position of the access policy in dashboard on switching>access policies page. If the first configuired access policy is wanted then enter 1 so on and so forth: ").strip()
                # Check if the input is a digit and within the range 1 to 8
                if access_Policy_Number.isdigit() and 1 <= int(access_Policy_Number) <= 8:
                    return access_Policy_Number
                else:
                    print("\033[1m\033[3m\033[31mInvalid input. Dashboard allows for a maximum of 8 access policies. Please enter the policy number, the number must be between 1 and 8.\033[0m\n")
    def isolation_enabled_Function(profile_Enabled):
        if profile_Enabled == "true":
            return
        valid_inputs = ["true", "false", ""]
        while True:
            isolation_enabled = input("Is isolation enabled? Enter true or false. Default value is false: ").strip().lower()
            if isolation_enabled in valid_inputs:
                return isolation_enabled
            else:
                print("\033[1m\033[3m\033[31mInvalid input. Please enter 'true', 'false', or leave blank to skip.\033[0m\n")
    def rstp_Enabled_Function(profile_Enabled):
        if profile_Enabled == "true":
            return
        valid_inputs = ["true", "false", ""]
        while True:
            rstp_Enabled = input("RSTP enabled? Enter true or false: ").strip().lower()
            if rstp_Enabled in valid_inputs:
                return rstp_Enabled
            else:
                print("\033[1m\033[3m\033[31mInvalid input. Please enter 'true', 'false', or leave blank to skip.\033[0m\n")
    def stp_Guard_Function(profile_Enabled):
        if profile_Enabled == "true":
            return
        valid_inputs = ["disabled", "root guard", "bpdu guard", "loop guard", ""]
        while True:
            stp_Guard = input("STP Guard feature? Enter disabled, root guard, bpdu guard, loop guard: ").strip().lower()
            if stp_Guard in valid_inputs:
                return stp_Guard
            else:
                print("\033[1m\033[3m\033[31mInvalid input. Please enter 'disabled, 'root guard', 'bpdu guard', 'loop guard', or leave blank to skip.\033[0m\n")
    def link_negotiation_Function(profile_Enabled):
        if profile_Enabled == "true":
            return
        valid_inputs = ["Auto negotiate", "1 Gigabit full duplex (forced)", "100 Megabit (auto)", "100 Megabit half duplex (forced)", "100 Megabit full duplex (forced)", "10 Megabit (auto)", "10 Megabit half duplex (forced)", "10 Megabit full duplex (forced)", ""]
        while True:
            link_negotiation = input("Enter the link negotiation configuration. Possible values are Auto negotiate, 1 Gigabit full duplex (forced), 100 Megabit (auto), 100 Megabit half duplex (forced), 100 Megabit full duplex (forced), 10 Megabit (auto), 10 Megabit half duplex (forced), 10 Megabit full duplex (forced): ").strip()
            if link_negotiation in valid_inputs:
                return link_negotiation
            else:
                print("\033[1m\033[3m\033[31mInvalid input. Make sure your entry matches exactly to one of the options given (including punctuation) or leave blank to skip.\033[0m\n")
    def port_Schedule_ID_Function(profile_Enabled):
        if profile_Enabled == "true":
            return
        else:
            port_Schedule_ID = input("Enter the port scheudle id. If no schedule enter none or leave blank to skip. It is recommended to manually set a port to the schedule and run a GET call to that switchport to get the schedule ID as this is auto genrated on the backend and not displayed within dashboard: ").strip()
            return port_Schedule_ID
    def udld_Function(profile_Enabled):
        if profile_Enabled == "true":
            return
        valid_inputs = ["Alert only", "Enforce", ""]
        while True:
            udld = input("Enter UDLD configuration. Either Alert only or Enforce: ").strip()
            if udld in valid_inputs:
                return udld
            else:
                print("\033[1m\033[3m\033[31mInvalid input. Please enter either 'Alert only', 'Enforce', or leave blank to skip.\033[0m\n")
    def dai_Trusted_Function(profile_Enabled):
        if profile_Enabled == "true":
            return
        valid_inputs = ["true", "false", ""]
        while True:
            dai_Trusted = input("DAI trusted port? Enter true or false: ").strip().lower()
            if dai_Trusted in valid_inputs:
                return dai_Trusted
            else:
                print("\033[1m\033[3m\033[31mInvalid input. Please enter 'true', 'false', or leave blank to skip.\033[0m\n")
    def adaptive_Policy_GroupId_Function(networkselection, tagselection, port_type, profile_Enabled):
        if profile_Enabled == "true":
            return
        try:
            response = dashboard.networks.getNetworkDevices(networkselection)
            all_devices_compatible = True  # Assume all devices are compatible initially
        except meraki.APIError as e:
            print(f"\033[1m\033[3m\033[31mMeraki API error:\033[0m\n {e}")
            return None
        except Exception as e:
            print(f"\033[1m\033[3m\033[31mSome other error occurred:\033[0m\n {e}")
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
            adaptive_Policy_GroupId = input("\nEnter the adaptive policy group ID number. The adaptive policy group ID that will be used to tag traffic through this switch port. This ID must pre-exist during the configuration, else it needs to be created using adaptivePolicy/groups API. Cannot be applied to a port bound to a port profile. *It is recommended to manually set a port in dashboard to the adaptive group # and then run a GET for the config of that port as this number is not the tag number you configured in dashboard but a unique string that dashboard applies in this field on the port config itself.*If adaptive policy is not enabled in the network leave this field blank: ").strip()
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
            print(f"\033[1m\033[3m\033[31mMeraki API error:\033[0m\n {e}")
            return None
        except Exception as e:
            print(f"\033[1m\033[3m\033[31mSome other error occurred:\033[0m\n {e}")
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
            peer_Sgt_Capable = input("Enable peer sgt (security group tag)? Enter true or false. If true, Peer SGT is enabled for traffic through this switch port. Applicable to trunk ports only, not access ports. Cannot be applied to a port on a switch bound to profile. If adaptive policy is not enabled in the network leave this field blank: ").strip()
        else:
            peer_Sgt_Capable = ""

        return peer_Sgt_Capable




    print("\n""\033[1m\033[31mIt is recommended to copy and paste exact values from the terminal prompts for configuration values to avoid errors, where applicable. If you do not want to include a configuration in your paramters within the API call and leave that configuration unchanged simply click enter with a blank value.\033[0m""\n")
    profile_Enabled = profile_Enabled_Function()
    profile_id = profile_id_Function(profile_Enabled)
    profile_iname = profile_iname_Function(profile_Enabled)
    port_enabled = port_enabled_Function(profile_Enabled)
    poe_enabled = poe_enabled_Function(profile_Enabled)
    port_type = port_type_Function(profile_Enabled)
    vlan = vlan_Function(profile_Enabled,port_type)
    voice_Vlan = voice_Vlan_Function(profile_Enabled,port_type)
    allowed_vlans = allowed_Vlans_Function(profile_Enabled,port_type)
    isolation_enabled = isolation_enabled_Function(profile_Enabled)
    rstp_Enabled = rstp_Enabled_Function(profile_Enabled)
    stp_Guard = stp_Guard_Function(profile_Enabled)
    link_negotiation = link_negotiation_Function(profile_Enabled)
    port_Schedule_ID = port_Schedule_ID_Function(profile_Enabled)
    udld = udld_Function(profile_Enabled) 
    access_policy = access_policy_Function(profile_Enabled,port_type)
    access_Policy_Number = access_Policy_Number_Function(profile_Enabled,access_policy)
    mac_Allow_List = mac_Allow_List_Function(profile_Enabled,access_policy)
    sticky_Mac_Allow_List = sticky_Mac_Allow_List_Function(profile_Enabled,access_policy)
    sticky_Mac_Allow_List_Limit = sticky_Mac_Allow_List_Limit_Function(profile_Enabled,access_policy)
    #Storm control not supported at this time. Whatever configuration is there will remain unchanged. storm_Control_Enabled = input("Storm control enabled? Enter true or false: ")
    dai_Trusted = dai_Trusted_Function(profile_Enabled)
    peer_Sgt_Capable = peer_Sgt_Capable_Function(networkselection,tagselection,port_type,profile_Enabled)
    adaptive_Policy_GroupId = adaptive_Policy_GroupId_Function(networkselection,tagselection,port_type,profile_Enabled)



    def configure_ports(serial_list, port_ids):
        action_list_1 = list()
        all_actions = list()
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
                
                action1 = dashboard.batch.switch.updateDeviceSwitchPort(serial, port, **kwargs)
                action_list_1.append(action1)
            all_actions.extend(action_list_1)
        execute_helper = batch_helper.BatchHelper(dashboard, orgselection, all_actions)

        execute_helper.prepare()
        execute_helper.generate_preview()
        execute_helper.execute()

        print(f'helper status is {execute_helper.status}')

        batches_report = dashboard.organizations.getOrganizationActionBatches(orgselection)
        new_batches_statuses = [{'id': batch['id'], 'status': batch['status']} for batch in batches_report if batch['id'] in execute_helper.submitted_new_batches_ids]
        failed_batch_ids = [batch['id'] for batch in new_batches_statuses if batch['status']['failed']]
        if failed_batch_ids:
            print(f'\033[1m\033[31mFailed batch IDs are as follows: {failed_batch_ids}\033[0m')
        if not failed_batch_ids:
            print(f'\033[1m\033[32mAll configurations were processed successfully.\033[0m')

    # Call the function with the serial numbers and port IDs
    configure_ports(serial_list, port_ids)

def configure_link_aggregation_choice():

    API_KEY = input("Please enter your API Key: ").strip()

    dashboard = meraki.DashboardAPI(API_KEY, suppress_logging=True)

    def get_org_id():
        while True:
            try:
                response = dashboard.organizations.getOrganizations()
                if not response:
                    print("\033[1m\033[3m\033[31mNo organizations found with the provided API key. Please ensure your API key is correct and try again.\033[0m")
                    return None

                valid_org_ids = {org['id'] for org in response}
                print(f"Here are the organizations that the API key has permissions to:\n")
                for org in response:
                    print(f"{org['name']} - {org['id']}")

                org_id = input("\nPlease enter the organization number you wish to configure: ").strip()
                if org_id in valid_org_ids:
                    return org_id
                else:
                    print("\033[1m\033[3m\033[31mThe entry did not match any of the organization IDs tied to that API key. Please try again.\033[0m")

            except meraki.APIError as e:
                if 400 <= e.status <= 499:
                    print(f"Client error occurred: {e.status} {e.reason}")
                    if e.status == 401:
                        print("\033[1m\033[3m\033[31mInvalid API key. Please ensure your API key is correct and try again.\033[0m")
                    return None
                else:
                    print(f"\033[1m\033[3m\033[31mMeraki API error:\033[0m {e}")
                    return None
            except Exception as e:
                print(f"\033[1m\033[3m\033[31mSome other error occurred:\033[0m {e}")
                return None

    # Loop to handle re-entry of the API key and fetching the organization ID
    while True:
        orgselection = get_org_id()
        if orgselection is None:
            # Prompt the user to enter the API key again
            api_key = input("Please enter your API Key: ").strip()
            dashboard = meraki.DashboardAPI(api_key=api_key, suppress_logging=True)
        else:
            break  # Valid organization ID was entered, exit the loop

    def get_network_names(orgselection):
        try:
            response = dashboard.organizations.getOrganizationNetworks(orgselection)
            sorted_networks = sorted(response, key=lambda net: net['name'])  # Sort networks alphabetically by name
            print(f"\nHere are the Networks within Organization {orgselection}:")
            for network in sorted_networks:
                print(network['name'], "-", network['id'])
            return sorted_networks  # Return the sorted list
        except meraki.APIError as e:
            print(f"\033[1m\033[3m\033[31mMeraki API error:\033[0m {e}")
            return None
        except Exception as e:
            print(f"\033[1m\033[3m\033[31mSome other error occurred:\033[0m {e}")
            return None

    # Get the list of networks for the selected organization
    network_names = get_network_names(orgselection)

    if network_names is None:
        print("\033[1m\033[3m\033[31mAn error occurred while retrieving the network names.\033[0m")
    else:
        # Extract valid network IDs for checking user input
        valid_network_ids = {network['id'] for network in network_names}

        # Loop to prompt the user for a valid network ID
        while True:
            networkId = input("\nPlease enter the network number you wish to configure: ").strip()
            if networkId in valid_network_ids:
                break  # The user entered a valid network ID
            else:
                print("\033[1m\033[3m\033[31mThe network number you entered is not valid for the selected organization. Please try again.\033[0m")

    def get_tags(networkId):
        try:
            response = dashboard.networks.getNetworkDevices(networkId)
        except meraki.APIError as e:
            print(f"\033[1m\033[3m\033[31mMeraki API error:\033[0m {e}")
            return set()  # Return an empty set on error
        except Exception as e:
            print(f"\033[1m\033[3m\033[31mSome other error occurred:\033[0m {e}")
            return set()  # Return an empty set on error

        seen_tags = set()  # Use a set to keep track of unique tags
        for device in response:
            if 'tags' in device and device.get('tags') and (device['model'].startswith('MS') or device['model'].startswith('C9')):
                device_tags = device['tags']
                for tag in device_tags:
                    if tag:  # Check if tag is not empty
                        seen_tags.add(tag.strip())  # Use strip() to remove any leading/trailing whitespace

        if not seen_tags:
            print("\033[1m\033[3m\033[31mNo tags found attached to any switches in the selected network. Please create and attach a tag to the switches you wish to configure with this program. You can reference this KB article on guidance with tags: https://documentation.meraki.com/MS/Monitoring_and_Reporting/Using_Tags_to_Manage_Switches\033[0m\n")
            return None  # Exit the function as there are no tags to proceed with

        # Print the tags separated by commas
        print(", ".join(sorted(seen_tags)))  # Sort tags alphabetically and join them into a string
        return seen_tags

    # Code to get the network selection and call the get_tags function
    # networkselection = 'your_network_id_here'
    seen_tags = get_tags(networkId)

    # If there are no tags, exit the function
    if seen_tags is None:
        exit(0)

    def tag_selection_function(seen_tags):
        while True:
            tagselection = input("\nPlease enter the switch tag you wish to configure: ").strip()
            if tagselection in seen_tags:
                return tagselection
            else:
                print(f"\033[1m\033[3m\033[31mInvalid input. You entered a tag name that is not assigned to any switches in the network you selected. Please enter one of the tag names:\033[0m {', '.join(sorted(seen_tags))}")

    # Call the tag_selection_function with the seen_tags
    tagselection = tag_selection_function(seen_tags)
    def get_tag_name(tagselection):
        try:
            response = dashboard.networks.getNetworkDevices(networkId)
        except meraki.APIError as e:
            print(f"\033[1m\033[3m\033[31mMeraki API error:\033[0m {e}")
            return None
        except Exception as e:
            print(f"\033[1m\033[3m\033[31mSome other error occurred:\033[0m {e}")
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
    print(f"\n\033[1m\033[3m\033[33mThe tag you have entered has matched to {serial_list_count} switches. Please double check this number equals the tag count in dashboard and is what you expect. Changes made via this program will impact all serial numbers assigned to this tag.\033[0m\n")

    def parse_range_to_numbers(portentry):
        entries = portentry.split(',')
        port_ids = []  # Initialize an empty list to store the port IDs
        module_pattern = re.compile(r'^(\d+_MA-MOD-\d+X\d+G_\d+)$')

        for entry in entries:
            entry = entry.strip()
            
            if module_pattern.match(entry):
                port_ids.append(entry)
                continue
            
            if '-' in entry:
                try:
                    start, end = map(int, entry.split('-'))
                    port_ids.extend(range(min(start, end), max(start, end) + 1))
                except ValueError:
                    raise ValueError(f"Invalid range '{entry}'. Please enter a valid range like '1-24'.")
                continue
            
            try:
                port_id = int(entry)
                port_ids.append(port_id)
            except ValueError:
                raise ValueError(f"Invalid port number '{entry}'. Please enter a valid number.")
        
        # Check for duplicates by converting the list to a set and comparing sizes
        if len(port_ids) != len(set(port_ids)):
            raise ValueError("Duplicate port numbers found. Please enter unique port numbers or ranges without overlap.")
        
        return sorted(set(port_ids))  # Return a sorted list of unique port IDs

        # Loop to prompt the user for input until valid, non-duplicate ports are entered
    while True:
        try:
            portentry = input("Please enter a port number and/or range. Multiple values can be entered separated with a comma (e.g., '1-24' or '24-1, 12'). For modules, use the format '1_MA-MOD-4X10G_1'. Module ports will need to be entered one by one separated by a comma: ")
            port_ids = parse_range_to_numbers(portentry)
            break  # Exit loop if parsing is successful and no exceptions are raised
        except ValueError as e:
            print(f"\033[1m\033[3m\033[31m{e}\033[0m\n")

    def configure_link_aggregation_Function(networkId, serial_list, port_ids):
        action_list_1 = list()
        all_actions = list()
        for serial in serial_list:
            # Construct the payload for this serial number with all the port IDs
            switch_ports = [{"serial": serial, "portId": str(port)} for port in port_ids]
            payload = {"switchPorts": switch_ports}

            # print(f"Calling createNetworkSwitchLinkAggregation with networkId={networkId} and payload={payload}") uncomment this line to help debug if needed

            # The API call to create a link aggregation
            # Pass networkId and payload as named arguments
            action1 = dashboard.batch.switch.createNetworkSwitchLinkAggregation(networkId=networkId, switchPorts=payload['switchPorts'])
            action_list_1.append(action1)
        all_actions.extend(action_list_1)
        execute_helper = batch_helper.BatchHelper(dashboard, orgselection, all_actions)

        execute_helper.prepare()
        execute_helper.generate_preview()
        execute_helper.execute()

        print(f'helper status is {execute_helper.status}')

        batches_report = dashboard.organizations.getOrganizationActionBatches(orgselection)
        new_batches_statuses = [{'id': batch['id'], 'status': batch['status']} for batch in batches_report if batch['id'] in execute_helper.submitted_new_batches_ids]
        failed_batch_ids = [batch['id'] for batch in new_batches_statuses if batch['status']['failed']]
        if failed_batch_ids:
            print(f'\033[1m\033[31mFailed batch IDs are as follows: {failed_batch_ids}\033[0m')
        if not failed_batch_ids:
            print(f'\033[1m\033[32mAll configurations were processed successfully.\033[0m')



    configure_link_aggregation_Function(networkId, serial_list, port_ids)


def main():
    while True:
        # Ask the user for the type of configuration they would like to perform
        config_selection = input("Enter 'ports' to configure ports, 'link aggregation' to configure LACP, or 'exit' to exit the program: ").strip().lower()

        if config_selection == 'ports':
            configure_ports_choice()
        elif config_selection == 'link aggregation':
            configure_link_aggregation_choice()
        elif config_selection == 'exit':
            print("\033[1m\033[32mExiting the program.\033[0m")
            break  # Break out of the loop to exit the program
        else:
            print("\033[1m\033[3m\033[31mInvalid selection. Please enter 'ports' or 'link aggregation'.\033[0m")

if __name__ == "__main__":
    main()