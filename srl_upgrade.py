from pygnmi.client import gNMIclient
import json
import argparse
import os
from deepdiff import DeepDiff
import pprint
import time
from jsondiff import diff
import logging
from datetime import datetime

def run_gnmi_query(gnmi_host,username,password,hostname,gnmi_path):
    
    with gNMIclient(target=gnmi_host, username=username, password=password, override=hostname) as gc:
        logging.debug('Running gnmi query, raw data to follow')
        raw_data = gc.get(path=[gnmi_path], encoding='json_ietf')
        logging.debug(raw_data)
        logging.debug('End of gnmi query data')
        return raw_data



def parse_gnmi_result(raw_data):
    #Parse the result of 1 GNMI query and return its results   

    try:
        if 'notification' in raw_data.keys():
            notifications = raw_data['notification']
            notification = notifications[0]
            if 'update' in notification.keys():
                updates = notification['update']
                update = updates[0]
                if 'val' in update.keys():
                    data = update['val']
                    if type(data) is dict:
                        keys = list(data.keys())
                        if len(keys) > 0:
                            #print (data)
                            return data[keys[0]]
                        else: return None
                    else: 
                        if type(data) is str and len(data) > 0:
                            return data
                        else: return None
    except Exception as ex:
        return None
    return None

#Provide backward compatability for v22
def parse_bgp_gnmi_v22(bgp_raw_data,hostname):
    tor_bgp_status = {}
    tor_bgp_status[hostname]= {}
    for peer in bgp_raw_data:
        #print (peer['peer-address']['afi-safi-name'])
        tor_bgp_status[hostname].update({peer['peer-address'] : {'session-state': peer['session-state'], 'address_family_ipv4_received_routes': peer['ipv4-unicast']['received-routes'], 'address_family_evpn_received_routes': peer['evpn']['received-routes'], 'address_family_ipv6_received_routes': peer['ipv6-unicast']['received-routes'] }})
    return tor_bgp_status  

#This data structure is assuming v23+ is now the standard
def parse_bgp_gnmi(bgp_raw_data,hostname):
    tor_bgp_status = {}
    tor_bgp_status[hostname]= {}
    tor_evpn_info = {}
    tor_ipv4_info = {}
    tor_ipv6_info = {}
    for peer in bgp_raw_data:
        for family in peer['afi-safi']:
            if family['afi-safi-name'] == 'srl_nokia-common:evpn':
                #tor_bgp_status[hostname].update({peer['peer-address'] : {'session-state': peer['session-state'], 'address_family_evpn_received_routes': family['received-routes'] }})
                tor_evpn_info = {'session-state': peer['session-state'], 'address_family_evpn_received_routes': family['received-routes']}
            elif family['afi-safi-name'] == 'srl_nokia-common:ipv4-unicast':
                #tor_bgp_status[hostname].update({peer['peer-address'] : {'session-state': peer['session-state'], 'address_family_ipv4_received_routes': family['received-routes'] }})
                tor_ipv4_info = {'session-state': peer['session-state'], 'address_family_ipv4_received_routes': family['received-routes']}
            elif family['afi-safi-name'] == 'srl_nokia-common:ipv6-unicast':
                #tor_bgp_status[hostname].update({peer['peer-address'] : {'session-state': peer['session-state'], 'address_family_ipv6_received_routes': family['received-routes'] }})
                tor_ipv6_info = {'session-state': peer['session-state'], 'address_family_ipv6_received_routes': family['received-routes']}
        
        tor_bgp_status[hostname].update({peer['peer-address']: {'session-state': peer['session-state'], 'address_family_evpn_received_routes' : tor_evpn_info['address_family_evpn_received_routes'], 'address_family_ipv4_received_routes': tor_ipv4_info['address_family_ipv4_received_routes'], 'address_family_ipv6_received_routes': tor_ipv6_info['address_family_ipv6_received_routes']}})
    return tor_bgp_status
def parse_srl_version(version_raw_data,hostname):
    tor_version = {}
    tor_version[hostname] = {}
    tor_version[hostname] = version_raw_data
    return tor_version


def parse_srl_applications(application_path_raw,hostname):
    tor_application = {}
    tor_application[hostname] = {}
    
    for app in application_path_raw:
        tor_application[hostname].update({app['name'] : app['state']})
    return tor_application


def parse_network_instances(network_instance_raw,hostname):
    tor_network_instance = {}
    tor_network_instance[hostname] = {}
    for vrf in network_instance_raw:
        tor_network_instance[hostname].update({vrf['name']:vrf['oper-state']})
    return tor_network_instance

def parse_arp_status(arp_status_raw,hostname):
    tor_arp_status = {}
    tor_arp_status[hostname] = {}
    for interface in arp_status_raw:
        if 'subinterface' in interface.keys():
            for subint in interface['subinterface']:
                if 'ipv4' in subint.keys(): #not all subinterfaces will have an ipv4 entry, check that
                    if 'neighbor' in subint['ipv4']['srl_nokia-interfaces-nbr:arp'].keys(): #check that there are neighbors listed under arp
                        tor_arp_status[hostname].update({subint['name'] : []}) #Create a key in the dictonary for the sub interface name if we know it will have arps
                        for neighbor in subint['ipv4']['srl_nokia-interfaces-nbr:arp']['neighbor']:
                            if neighbor['origin'] == 'dynamic': 
                                #Only save data that has a dynamic entry, not evpn routes
                                #Append the ipv4 address, mac etc in a list 
                                # Skip what's on the mgmt interface
                                if 'mgmt0.0' in subint['name']: 
                                    continue
                                else:
                                    #changing structure
                                    #tor_arp_status[hostname][subint['name']].append({'ipv4_address' : neighbor['ipv4-address'],'mac_address' : neighbor['link-layer-address']})
                                    tor_arp_status[hostname][subint['name']].append({neighbor['ipv4-address'] : neighbor['link-layer-address']})
    return tor_arp_status


def parse_interface_status(interface_raw_data,hostname):
    tor_interface_status = {}
    tor_interface_status[hostname] = {}
    for port in interface_raw_data:
        #If port has no description configured, there is not default value, so check keys first if has it, save it, if not just get port op status
        if 'description' in port.keys():
            tor_interface_status[hostname].update({port['name']: {'port_description' :port['description'], 'port_oper_state': port['oper-state']}})
        else:
            tor_interface_status[hostname].update({port['name']: {'port_oper_state' : port['oper-state']}})
    return tor_interface_status

def check_bouncing_ports(gnmi_host,username,password,hostname):
    tor_port_status = {}
    tor_port_status[hostname] = {}
    tor_port_status_recheck = {}
    tor_port_status_recheck[hostname] = {}
    gnmi_path = '/interface/'
    interface_raw_data = run_gnmi_query(gnmi_host,username,password,hostname,gnmi_path)
    interface_status_parsed_data = parse_gnmi_result(interface_raw_data)
    print ('Checking initial state change time for interfaces..')
    for interface in interface_status_parsed_data:
        #Admin disabled ports do not have stats, nor do irb/loopbacks or system so continue in loop
        if interface['admin-state'] == 'disable' or 'irb' in interface['name'] or 'lo' in interface['name'] or 'system' in interface['name']:
            continue
        try:
            tor_port_status[hostname].update({interface['name'] : {'state_change' : interface['last-change'], 'in_errors' : interface['statistics']['in-error-packets'], 
                                                               'out_errors' : interface['statistics']['out-error-packets'], 'port_issues' : False} })
        except: print (interface['name'] + ' did not have stats, most likley port is up but never passed traffic. continuing..')
    print ('Sleeping 10 seconds to check for port flaps..')
    time.sleep(10)
    #Loop through calls again, and build a secondary dictonary to compare new values to
    interface_raw_data = run_gnmi_query(gnmi_host,username,password,hostname,gnmi_path)
    interface_status_parsed_data = parse_gnmi_result(interface_raw_data)

    for interface in interface_status_parsed_data:
        #Admin disabled ports do not have stats, so continue in loop
        if interface['admin-state'] == 'disable' or 'irb' in interface['name'] or 'lo' in interface['name'] or 'system' in interface['name']:
            continue
        try:
            tor_port_status_recheck[hostname].update({interface['name'] : {'state_change' : interface['last-change'], 'in_errors' : interface['statistics']['in-error-packets'], 
                                                               'out_errors' : interface['statistics']['out-error-packets'], 'port_issues' : False} })
        except: print (interface['name'] + ' did not have stats, most likley port is up but never passed traffic. continuing..')
    #loop through old and new data, and check if the state has changed. If it has then mark that it is flapped or has erros, and in our checked data we will print out if anything
    #has changed later. 
    for interface in tor_port_status[hostname]:
        if tor_port_status[hostname][interface]['state_change'] == tor_port_status_recheck[hostname][interface]['state_change']:
            if tor_port_status[hostname][interface]['in_errors'] == tor_port_status_recheck[hostname][interface]['in_errors']:
                if tor_port_status[hostname][interface]['out_errors'] == tor_port_status_recheck[hostname][interface]['out_errors']:
                    continue
        else:
            tor_port_status[hostname][interface]['port_issues'] = True
    
    return tor_port_status

def report_port_issues(port_status,hostname):
    print ('Checking for any port that has flapped or errors incrementing...')
    issues_found = False
    for interface in port_status[hostname]:
        if port_status[hostname][interface]['port_issues'] == True:
            print ('\033[1;31m This port is flapping or errors incrementing: ' + interface + '\033[0;0m')
            issues_found = True
        else: continue
    if issues_found == False:
        print ('\033[1;32m No issues found with port errors or flaps \033[0;0m')
def generate_port_shutdown(tor_port_status,gnmi_host,username,password,hostname):
    tor_access_ports_for_shutdown = {}
    tor_access_ports_for_shutdown[hostname] = []
    port_is_uplink = False
    gnmi_path = '/network-instance[name=default]/interface/'
    interface_base_data = run_gnmi_query(gnmi_host,username,password,hostname,gnmi_path)
    interface_base_parsed_data = parse_gnmi_result(interface_base_data)
    for port in tor_port_status[hostname]:
        #We only care about ports that are up to later shutdown
        if tor_port_status[hostname][port]['port_oper_state'] == 'up':
            for base_port in interface_base_parsed_data:
                base_port_no_sub = base_port['name'].split('.')
                #This is hacky.. but the problem is looking in the default network instance, those interfaces will be xx.sub interface. 
                #to match properly with normal ethernet ports, above splits the network instance interfaces so it will just be ethernetx/x and not the ethernetx/x.x
                if port == base_port_no_sub[0]:
                    port_is_uplink = True
                    break
            if port_is_uplink == False:
                #We don't want to shutdown irbs, los, system or mgmt ports so skip them
                if 'irb' not in port:
                    if 'lo' not in port:
                        if 'system' not in port:
                            if 'mgmt' not in port: 
                                    tor_access_ports_for_shutdown[hostname].append(port)
                continue
            else: 
                port_is_uplink = False
                continue
    return tor_access_ports_for_shutdown
def shutdown_access_ports(tor_access_ports_for_shutdown,gnmi_host,username,password,hostname):
    print (f"Script is now ready to shutdown ports to prepare for upgrade, these are the ports that will be shutdown:")
    print (tor_access_ports_for_shutdown)
    answer = input("Enter Y or N for shutting down the ports: ")
    if answer == "Y":
        for port in tor_access_ports_for_shutdown[hostname]:
            gnmi_path = (f"interface[name={port}]",
                           {"admin-state": "disable"}
                         )
                        
            print (gnmi_path)
            run_gnmi_set(gnmi_host,username,password,hostname,gnmi_path)
    else: print ("Input was N, or not proper input. Exiting, but data has been saved for upgrade")

def enter_bgp_maint_mode(gnmi_host,username,password,hostname):
    print (f"Script is now ready to put the device into bgp maintenance mode. Should this be executed?")
    answer = input("Enter Y or N to execute bgp maintenance mode: ")
    if answer == "Y":
        gnmi_path = (f"/system/maintenance/group[name=ebgp-ipv4-maintenance]/maintenance-mode/",
                     {"admin-state" : "enable"}
                     )
        print (gnmi_path)
        run_gnmi_set(gnmi_host,username,password,hostname,gnmi_path)
    else: print ("Input was N, or not proper input. Continuning, but data has been saved for upgrade")

def exit_bgp_maint_mode(gnmi_host,username,password,hostname):
    print (f"Script is now ready to exit the device out of bgp maintenance mode. Should this be executed?")
    answer = input("Enter Y or N to exit bgp maintenance mode: ")
    if answer == "Y":
        logging.debug('User entered Y, and running GNMI commands to exit BGP maint mode')
        gnmi_path = (f"/system/maintenance/group[name=ebgp-ipv4-maintenance]/maintenance-mode/",
                     {"admin-state" : "disable"}
                     )
        #print (gnmi_path)
        run_gnmi_set(gnmi_host,username,password,hostname,gnmi_path)
        logging.debug('End of exit of bgp maint mode function')
    else: print ("Input was N, or not proper input. Continuning, without exiting bgp maintenance mode")

def no_shutdown_access_ports(gnmi_host,username,password,hostname):
    tor_ports_no_shutdown_file = open(hostname+'-before'+'/'+hostname+'-port-shutdown-summary'+'.json')
    tor_ports_no_shutdown = json.load(tor_ports_no_shutdown_file)
    print ('These ports will be no shutdown now that were saved from before the upgrade')
    print (tor_ports_no_shutdown)
    for port in tor_ports_no_shutdown[hostname]:
        gnmi_path = (f"interface[name={port}]",
                           {"admin-state": "enable"}
                         )
        print (gnmi_path)
        #interface[name=ethernet1/1] {admin-state: enable} 
        run_gnmi_set(gnmi_host,username,password,hostname,gnmi_path)
def run_gnmi_set(gnmi_host,username,password,hostname,gnmi_path):
    with gNMIclient(target=gnmi_host, username=username, password=password, override=hostname) as gc:
        raw_data = gc.set(update=[gnmi_path])
        logging.debug('running gnmi set, raw_data to follow')
        logging.debug(raw_data)
        logging.debug('end of raw_data from gnmi set command')
        #raw_data = gc.set()

def parse_fan_status(fan_raw_data,hostname):
    tor_fan_status = {}
    tor_fan_status[hostname] = {}
    for fan in fan_raw_data:
        tor_fan_status[hostname].update({fan['id'] : fan['oper-state']})
    return tor_fan_status

def parse_power_supply_status(power_supply_raw_data,hostname):
    tor_power_supply_status = {}
    tor_power_supply_status[hostname] = {}
    for fan in power_supply_raw_data:
        tor_power_supply_status.update({fan['id']: fan['oper-state']})
    return tor_power_supply_status

def parse_control_status(control_status_raw,hostname):
    tor_control_status = {}
    tor_control_status[hostname] = {}
    for card in control_status_raw:
        #print (card['slot'])
        tor_control_status.update({card['slot']: {'card_type' : card['type'], 'card_oper_status': card['oper-state']}})
    return tor_control_status

def parse_linecard_status(linecard_status_raw,hostname):
    tor_linecard_status = {}
    tor_linecard_status[hostname] = {}
    for card in linecard_status_raw:
        tor_linecard_status.update({card['slot']: {'card_type' : card['type'], 'card_oper_status': card['oper-state']}})
    return tor_linecard_status

def parse_mac_information(network_instance_raw,hostname):
    tor_mac_vrf_information = {}
    tor_mac_vrf_information[hostname] = {}
    for service in network_instance_raw:
        if service['type'] == 'srl_nokia-network-instance:mac-vrf':
            #Only grab services that have mac addresses in it
            if len(service['bridge-table']['mac-learning']['srl_nokia-bridge-table-mac-learning-entries:learnt-entries']) >=1:
                tor_mac_vrf_information[hostname].update({service['name'] : []}) #update dictonary with key for service name, so we can append macs to it later. 
                for mac in service['bridge-table']['mac-learning']['srl_nokia-bridge-table-mac-learning-entries:learnt-entries']['mac']:
                    #changing structure
                    #tor_mac_vrf_information[hostname][service['name']].append({'mac_address' : mac['address'],'interface_leanred' : mac['destination']})
                    tor_mac_vrf_information[hostname][service['name']].append({mac['address']:  mac['destination']})

    return tor_mac_vrf_information
    
def parse_tunnel_information(tunnel_data_raw,hostname):
    tor_tunnel_information = {}
    tor_tunnel_information[hostname] = []
    try:
        for tunnel in tunnel_data_raw['vtep']:
            tor_tunnel_information[hostname].append(tunnel['address'])
    except: 
        print ('Appear to be running on a spine or leaf with no VTEPs. If not expected, examine node and script. Continuing.. ')
    return tor_tunnel_information
def save_data(tor_bgp_status,tor_version,tor_application_status,network_instance_status,interface_status,fan_status,power_supply_status,control_status,linecard_status,arp_status,mac_information_status,tunnel_status,port_status,tor_access_ports_for_shutdown,hostname,before_or_after_flag):

    if before_or_after_flag == 'precheck':
        try:
            os.mkdir(hostname+'-before')
            print ('making directory')
        except: print ('folder exists, continuning')
        with open(hostname+'-before'+'/'+hostname+'-version'+'.json', "w") as outfile:
            json.dump(tor_version, outfile)
        print ('writing version data')
        with open(hostname+'-before'+'/'+hostname+'-bgp-summary'+'.json', "w") as outfile:
            json.dump(tor_bgp_status, outfile)
        print ('writing bgp data')
        with open(hostname+'-before'+'/'+hostname+'-app-summary'+'.json', "w") as outfile:
            json.dump(tor_application_status, outfile)
        print ('writing app data')
        with open(hostname+'-before'+'/'+hostname+'-network-instance-summary'+'.json', "w") as outfile:
            json.dump(network_instance_status, outfile)
        print ('writing network instance data')
        with open(hostname+'-before'+'/'+hostname+'-interface-summary'+'.json', "w") as outfile:
            json.dump(interface_status, outfile)
        print ('writing interface summary data')
        with open(hostname+'-before'+'/'+hostname+'-fan-summary'+'.json', "w") as outfile:
            json.dump(fan_status, outfile)
        print ('writing fan data')
        with open(hostname+'-before'+'/'+hostname+'-power-summary'+'.json', "w") as outfile:
            json.dump(power_supply_status, outfile)
        print ('writing power data')
        with open(hostname+'-before'+'/'+hostname+'-control-summary'+'.json', "w") as outfile:
            json.dump(control_status, outfile)
        print ('writing control data')
        with open(hostname+'-before'+'/'+hostname+'-linecard-summary'+'.json', "w") as outfile:
            json.dump(linecard_status, outfile)
        print ('writing linecard data')
        with open(hostname+'-before'+'/'+hostname+'-arp-summary'+'.json', "w") as outfile:
            json.dump(arp_status, outfile)
        print ('writing arp data')
        with open(hostname+'-before'+'/'+hostname+'-mac-summary'+'.json', "w") as outfile:
            json.dump(mac_information_status, outfile)
        print ('writing mac address data')
        with open(hostname+'-before'+'/'+hostname+'-tunnel-summary'+'.json', "w") as outfile:
            json.dump(tunnel_status, outfile)
        print ('writing tunnel data')
        with open(hostname+'-before'+'/'+hostname+'-port-summary'+'.json', "w") as outfile:
            json.dump(port_status, outfile)
        print ('writing port data')
        with open(hostname+'-before'+'/'+hostname+'-port-shutdown-summary'+'.json', "w") as outfile:
            json.dump(tor_access_ports_for_shutdown, outfile)
        print ('writing ports for shutdown')
    if before_or_after_flag == 'postcheck':
        try:
            os.mkdir(hostname+'-after')
            print ('making directory')
        except: print ('folder exists, continuning')
        with open(hostname+'-after'+'/'+hostname+'-version'+'.json', "w") as outfile:
            json.dump(tor_version, outfile)
        print ('writing version data')
        with open(hostname+'-after'+'/'+hostname+'-bgp-summary'+'.json', "w") as outfile:
            json.dump(tor_bgp_status, outfile)
        print ('writing bgp data')
        with open(hostname+'-after'+'/'+hostname+'-app-summary'+'.json', "w") as outfile:
            json.dump(tor_application_status, outfile)
        print ('writing app data')
        with open(hostname+'-after'+'/'+hostname+'-network-instance-summary'+'.json', "w") as outfile:
            json.dump(network_instance_status, outfile)
        print ('writing network instance data')
        with open(hostname+'-after'+'/'+hostname+'-interface-summary'+'.json', "w") as outfile:
            json.dump(interface_status, outfile)
        print ('writing interface summary data')
        with open(hostname+'-after'+'/'+hostname+'-fan-summary'+'.json', "w") as outfile:
            json.dump(fan_status, outfile)
        print ('writing fan data')
        with open(hostname+'-after'+'/'+hostname+'-power-summary'+'.json', "w") as outfile:
            json.dump(power_supply_status, outfile)
        print ('writing power data')
        with open(hostname+'-after'+'/'+hostname+'-control-summary'+'.json', "w") as outfile:
            json.dump(control_status, outfile)
        print ('writing control data')
        with open(hostname+'-after'+'/'+hostname+'-linecard-summary'+'.json', "w") as outfile:
            json.dump(linecard_status, outfile)
        print ('writing linecard data')
        with open(hostname+'-after'+'/'+hostname+'-arp-summary'+'.json', "w") as outfile:
            json.dump(arp_status, outfile)
        print ('writing arp data')
        with open(hostname+'-after'+'/'+hostname+'-mac-summary'+'.json', "w") as outfile:
            json.dump(mac_information_status, outfile)
        print ('writing mac address data')
        with open(hostname+'-after'+'/'+hostname+'-tunnel-summary'+'.json', "w") as outfile:
            json.dump(tunnel_status, outfile)
        print ('writing tunnel data')
        with open(hostname+'-after'+'/'+hostname+'-port-summary'+'.json', "w") as outfile:
            json.dump(port_status, outfile)
        print ('writing port data')
        
def compare_data(hostname):
    before_version_file = open(hostname+'-before'+'/'+hostname+'-version'+'.json')
    before_version = json.load(before_version_file)
    after_version_file = open(hostname+'-after'+'/'+hostname+'-version'+'.json')
    after_version = json.load(after_version_file)
    
    version_diff = DeepDiff(before_version,after_version)
    version_diff_dict = version_diff.to_dict()

    if version_diff_dict:
        print(""" 
    *********************
    Version Status Difference
    ********************""")
        for difference in version_diff_dict:
            print ('\033[1;31m Differences were found before and after for version status with type: ' + difference + '\033[0;0m')
            for entry in version_diff_dict[difference]:
                print (entry)
                print (version_diff_dict[difference][entry])
    else:
        print ('\033[1;32m No difference was found with software version \033[0;0m')


    before_bgp_status_file = open(hostname+'-before'+'/'+hostname+'-bgp-summary'+'.json')
    before_bgp_status = json.load(before_bgp_status_file)
    after_bgp_status_file = open(hostname+'-after'+'/'+hostname+'-bgp-summary'+'.json')
    after_bgp_status = json.load(after_bgp_status_file)
    bgp_status_diff = DeepDiff(before_bgp_status,after_bgp_status)
    bgp_status_diff_dict = bgp_status_diff.to_dict()
    if bgp_status_diff_dict:
        print(""" 
            *********************
            BGP Status Difference
            ********************""")
        for difference in bgp_status_diff_dict:
            print ('\033[1;31m Differences were found before and after for bgp status with type: ' + difference + '\033[0;0m')
            for entry in bgp_status_diff_dict[difference]:
                print (entry)
                try:
                    print (bgp_status_diff_dict[difference][entry])
                except: continue
    else: print ('\033[1;32m No differences were found with BGP peer status \033[0;0m')
    #App status
    before_app_status_file = open(hostname+'-before'+'/'+hostname+'-app-summary'+'.json')
    before_app_status = json.load(before_app_status_file)
    after_app_status_file = open(hostname+'-after'+'/'+hostname+'-app-summary'+'.json')
    after_app_status = json.load(after_app_status_file)
    app_status_diff = DeepDiff(before_app_status,after_app_status)
    app_status_diff_dict = app_status_diff.to_dict()

    if app_status_diff_dict:
        print(""" 
    *********************
    App Status Difference
    ********************""")
        for difference in app_status_diff_dict:
            if difference == 'dictionary_item_added':
                for entry in app_status_diff_dict[difference]:
                    print ("\033[1;31m New APP was found after upgrade \033[0;0m")
                    print(entry)
                    
            if difference == 'values_changed':
                for entry in app_status_diff_dict[difference]:
                    print ("\033[1;31m Existing app status status changed after upgrade: \033[0;0m")
                    print ('app name: ' + entry)
                    print (app_status_diff_dict[difference][entry])
                    
            
    else: print ('\033[1;32m No differences were found with app status \033[0;0m')
    
    print (""" 
    
    """)
    #Network Insance
    before_network_instance_file = open(hostname+'-before'+'/'+hostname+'-network-instance-summary'+'.json')
    before_network_instance_status = json.load(before_network_instance_file)
    after_network_instance_file = open(hostname+'-after'+'/'+hostname+'-network-instance-summary'+'.json')
    after_network_instance_status = json.load(after_network_instance_file)
    network_instance_diff = DeepDiff(before_network_instance_status,after_network_instance_status)
    network_instance_diff_dict = network_instance_diff.to_dict()

    if network_instance_diff_dict:
        print(""" 
    *********************
    Network Instance Status Difference
    ********************""")
        for difference in network_instance_diff:
            print ('\033[1;31m Differences were found before and after for network instances with type: ' + difference + '\033[0;0m')
            for entry in network_instance_diff[difference]:
                print (entry)
                print (network_instance_diff[difference][entry])
    else: print ('\033[1;32m No differences were found with network instance status \033[0;0m')

    #Interface status
    before_interface_status_file = open(hostname+'-before'+'/'+hostname+'-interface-summary'+'.json')
    before_interface_status_status = json.load(before_interface_status_file)
    after_interface_status_file = open(hostname+'-after'+'/'+hostname+'-interface-summary'+'.json')
    after_interface_status_status = json.load(after_interface_status_file)
    interface_summary_diff = DeepDiff(before_interface_status_status,after_interface_status_status)
    interface_summary_diff_dict = interface_summary_diff.to_dict()

    if interface_summary_diff_dict:
        print(""" 
    *********************
    Interface Status Difference
    ********************""")
        for difference in interface_summary_diff_dict:
            print ('\033[1;31m Differences were found before and after for network instances with type: ' + difference +'\033[0;0m')
            for entry in interface_summary_diff_dict[difference]:
                print (entry)
                print (interface_summary_diff_dict[difference][entry])
    else: print ('\033[1;32m No differences were found with port status \033[0;0m')
    
    #Fan status
    before_fan_status_file = open(hostname+'-before'+'/'+hostname+'-fan-summary'+'.json')
    before_fan_status = json.load(before_fan_status_file)
    after_fan_status_file = open(hostname+'-after'+'/'+hostname+'-fan-summary'+'.json')
    after_fan_status = json.load(after_fan_status_file)
    fan_summary_diff = DeepDiff(before_fan_status,after_fan_status)
    fan_summary_diff_dict = fan_summary_diff.to_dict()

    if fan_summary_diff_dict:
        print(""" 
    *********************
    Fan Status Difference
    ********************""")
        for difference in fan_summary_diff_dict:
            print ('\033[1;31m Differences were found before and after for network instances with type: ' + difference +'\033[0;0m') 
            for entry in fan_summary_diff_dict[difference]:
                print (entry)
                print (fan_summary_diff_dict[difference][entry])
    else: print ('\033[1;32m No differences were found with fan status \033[0;0m')

    #Power status
    before_power_status_file = open(hostname+'-before'+'/'+hostname+'-power-summary'+'.json')
    before_power_status = json.load(before_power_status_file)
    after_power_status_file = open(hostname+'-after'+'/'+hostname+'-power-summary'+'.json')
    after_power_status = json.load(after_power_status_file)
    power_summary_diff = DeepDiff(before_power_status,after_power_status)
    power_summary_diff_dict = power_summary_diff.to_dict()

    if power_summary_diff_dict:
        print(""" 
    *********************
    Power Status Difference
    ********************""")
        for difference in power_summary_diff_dict:
            print ('\033[1;31m Differences were found before and after for network instances with type: ' + difference +'\033[0;0m')
            for entry in power_summary_diff_dict[difference]:
                print (entry)
                print (power_summary_diff_dict[difference][entry])
    else: print ('\033[1;32m No differences were found with power status \033[0;0m')
    #control status

    before_control_status_file = open(hostname+'-before'+'/'+hostname+'-control-summary'+'.json')
    before_control_status = json.load(before_control_status_file)
    after_control_status_file = open(hostname+'-after'+'/'+hostname+'-control-summary'+'.json')
    after_control_status = json.load(after_control_status_file)
    control_summary_diff = DeepDiff(before_control_status,after_control_status)
    control_summary_diff_dict = control_summary_diff.to_dict()

    if control_summary_diff_dict:
        print(""" 
    *********************
    Control Status Difference
    ********************""")
        for difference in control_summary_diff_dict:
            print ('\033[1;31m Differences were found before and after for network instances with type: ' + difference + '\033[0;0m')
            for entry in control_summary_diff_dict[difference]:
                print (entry)
                print (control_summary_diff_dict[difference][entry])
    else: print ('\033[1;32m No differences were found with power status \033[0;0m')

    #linecard status
    
    before_linecard_status_file = open(hostname+'-before'+'/'+hostname+'-linecard-summary'+'.json')
    before_linecard_status = json.load(before_linecard_status_file)
    after_linecard_status_file = open(hostname+'-after'+'/'+hostname+'-linecard-summary'+'.json')
    after_linecard_status = json.load(after_linecard_status_file)
    linecard_summary_diff = DeepDiff(before_linecard_status,after_linecard_status)
    linecard_summary_diff_dict = linecard_summary_diff.to_dict()

    if linecard_summary_diff_dict:
        print(""" 
    *********************
    Linecard Status Difference
    ********************""")
        for difference in linecard_summary_diff_dict:
            print ('Differences were found before and after for network instances with type: ' + difference)
            for entry in linecard_summary_diff_dict[difference]:
                print (entry)
                print (linecard_summary_diff_dict[difference][entry])
    else: print ('\033[1;32m No differences were found with linecard status \033[0;0m')

    #Arp status
    before_arp_status_file = open(hostname+'-before'+'/'+hostname+'-arp-summary'+'.json')
    before_arp_status = json.load(before_arp_status_file)
    after_arp_status_file = open(hostname+'-after'+'/'+hostname+'-arp-summary'+'.json')
    after_arp_status = json.load(after_arp_status_file)
    
    arp_summary_diff = DeepDiff(before_arp_status,after_arp_status)

    arp_summary_diff_dict = arp_summary_diff.to_dict()
    if arp_summary_diff_dict:
        #print (arp_summary_diff_dict)
        print(""" 
    *********************
    Arp Status Difference
    ********************""")
        for difference in arp_summary_diff_dict:
            print ('\033[1;31m Differences were found before and after for dynamic ARP entries: ' + difference + '\033[0;0m')
            for entry in arp_summary_diff_dict[difference]:
                print ('Interface name: ' + entry)
                try:
                    print (arp_summary_diff_dict[difference][entry])
                except: continue
        
    else: print ('\033[1;32m No differences were found with dynamic arp entries \033[0;0m')

    #mac status
    before_mac_status_file = open(hostname+'-before'+'/'+hostname+'-mac-summary'+'.json')
    before_mac_status = json.load(before_mac_status_file)
    after_mac_status_file = open(hostname+'-after'+'/'+hostname+'-mac-summary'+'.json')
    after_mac_status = json.load(after_mac_status_file)
    mac_summary_diff = DeepDiff(before_mac_status,after_mac_status, ignore_order=True)
    mac_summary_diff_dict = mac_summary_diff.to_dict()
    #json_diff = diff(before_mac_status,after_app_status)
    #print (json_diff)
    if mac_summary_diff_dict:
        print(""" 
    *********************
    Mac Status Difference
    ********************""")
        for difference in mac_summary_diff_dict:
            print ('\033[1;31m Differences were found before and after for dynamic mac entries: ' + difference + '\033[0;0m')
            for entry in mac_summary_diff_dict[difference]:
                #print (mac_summary_diff_dict)
                print ('network status name: ' + entry)
                try:
                    print (mac_summary_diff_dict[difference][entry])
                except: continue
    else: print ('\033[1;32m No differences were found with dynamic mac entries \033[0;0m')
    #Tunnel status 
    before_tunnel_status_file = open(hostname+'-before'+'/'+hostname+'-tunnel-summary'+'.json')
    before_tunnel_status = json.load(before_tunnel_status_file)
    after_tunnel_status_file = open(hostname+'-after'+'/'+hostname+'-tunnel-summary'+'.json')
    after_tunnel_status = json.load(after_tunnel_status_file)
    tunnel_summary_diff = DeepDiff(before_tunnel_status,after_tunnel_status)

    tunnel_summary_diff_dict = tunnel_summary_diff.to_dict()
    
    if tunnel_summary_diff_dict:
        print(""" 
    *********************
    Tunnel Status Difference
    ********************""")
        for difference in tunnel_summary_diff_dict:
            print ('\033[1;31m Differences were found before and after for vxlan tunnel entries: ' + difference + '\033[0;0m')
            for entry in tunnel_summary_diff_dict[difference]:
                print (tunnel_summary_diff_dict[difference][entry])
    else: print ('\033[1;32m No differences were found with vxlan tunnel entries \033[0;0m')


    '''
    This should be covered for interface status abovse for physical interfaces as well
    #Port status
    before_port_status_file = open(hostname+'-before'+'/'+hostname+'-port-summary'+'.json')
    before_port_status = json.load(before_port_status_file)
    after_port_status_file = open(hostname+'-after'+'/'+hostname+'-port-summary'+'.json')
    after_port_status = json.load(after_port_status_file)
    port_summary_diff = DeepDiff(before_port_status,after_port_status)
    port_summary_diff_dict = port_summary_diff.to_dict()
    if port_summary_diff_dict:
        print(""" 
    *********************
    Port Status Difference
    ********************""")
        for difference in port_summary_diff_dict:
            print ('\033[1;31m Differences were found before and after for port status entries: ' + difference + '\033[0;0m')
            print (port_summary_diff_dict)
            for entry in port_summary_diff_dict[difference]:
                print (port_summary_diff_dict[difference][entry])
    '''
def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('-tor_ip', action='store', required=True,
                        help=('Mgmt IP of SRL TOR'))
    parser.add_argument('-username', action='store', required=True,
                        help=('username to login to SRL TOR'))
    parser.add_argument('-hostname', action='store', required=True,
                        help=('Hostname of SRL TOR'))
    parser.add_argument('-password', action='store', required=True, help=('Password for SRL TOR login'))
    parser.add_argument('-pre_check', action='store', required=False, help=('set flag if checking tor before reboot'))
    parser.add_argument('-post_check', action='store', required=False, help=('set flag after tor has rebooted to do post checks'))
    parser.add_argument('-no_shut_ports', action='store', required=False, help=('set flag if you only want to no shutdown ports and exit bgp maint mode'))
    parser.add_argument('-debug',action='store', help='Set flag for debug to log all data to files')
    args = parser.parse_args()
    gnmi_host = ()
    gnmi_host=(args.tor_ip,'57400')
    #gnmi_host=(args.tor_ip,'50001')
    if args.debug:
        logging.basicConfig(filename=(f'srl_upgrade_debug-{datetime.now().strftime("%Y-%m-%d-%H:%M:%S")}.log'), filemode='w',level=logging.DEBUG, format='%(asctime)s %(message)s')
        logging.debug('Starting debug file')
    if args.no_shut_ports:
        logging.debug('No shutdown ports variable set. Running exit of BGP commands and no shutdown ports')
        exit_bgp_maint_mode(gnmi_host,args.username,args.password,args.hostname)
        no_shutdown_access_ports(gnmi_host,args.username,args.password,args.hostname)
        logging.debug('Finish no shutdown of ports')
        exit()
    #get current version
    gnmi_path = '/system/information/version'
    logging.debug('Getting TOR version')
    version_raw_data = run_gnmi_query(gnmi_host,args.username,args.password,args.hostname,gnmi_path)
    tor_version_data = parse_gnmi_result(version_raw_data)
    tor_version = parse_srl_version(tor_version_data,args.hostname)
    


    #Check application status
    gnmi_path = '/system/app-management/application'
    logging.debug('Getting TOR app status')
    application_path_raw = run_gnmi_query(gnmi_host,args.username,args.password,args.hostname,gnmi_path)
    tor_application_status_parsed_data = parse_gnmi_result(application_path_raw)
    tor_application_status = parse_srl_applications(tor_application_status_parsed_data,args.hostname)
    
    #Check network-instances
    gnmi_path = '/network-instance/'
    logging.debug('Getting TOR network instance data')
    network_instance_raw = run_gnmi_query(gnmi_host,args.username,args.password,args.hostname,gnmi_path)
    network_instance_parsed_data = parse_gnmi_result(network_instance_raw)
    network_instance_status = parse_network_instances(network_instance_parsed_data,args.hostname)

    #get mac table information, and re-use the data from the network instance data
    mac_information_status = parse_mac_information(network_instance_parsed_data,args.hostname)
    
    #Run BGP checks v22
    if 'v22' in tor_version[args.hostname]:
        gnmi_path = '/network-instance[name=default]/protocols/bgp/neighbor'
        logging.debug('TOR appears to be on v22, run special checks for BGP info')
        bgp_raw_data = run_gnmi_query(gnmi_host,args.username,args.password,args.hostname,gnmi_path)
        tor_bgp_status_parsed_data = parse_gnmi_result(bgp_raw_data)
        tor_bgp_status = parse_bgp_gnmi_v22(tor_bgp_status_parsed_data,args.hostname)
    else:
        gnmi_path = '/network-instance[name=default]/protocols/bgp/neighbor'
        logging.debug('TOR is on code with newer BGP formating, getting BGP information')
        bgp_raw_data = run_gnmi_query(gnmi_host,args.username,args.password,args.hostname,gnmi_path)
        tor_bgp_status_parsed_data = parse_gnmi_result(bgp_raw_data)
        tor_bgp_status = parse_bgp_gnmi(tor_bgp_status_parsed_data,args.hostname)

    
    #Run Interface checks
    gnmi_path = '/interface/'
    logging.debug('Getting TOR interface data')
    interface_raw_data = run_gnmi_query(gnmi_host,args.username,args.password,args.hostname,gnmi_path)
    interface_status_parsed_data = parse_gnmi_result(interface_raw_data)
    interface_status = parse_interface_status(interface_status_parsed_data,args.hostname)
    

    

    #Gather ARP table. This uses the data already gathered from the interface context
    logging.debug('Parsing arp status')
    arp_status = parse_arp_status(interface_status_parsed_data,args.hostname)

    #Run fan checks
    gnmi_path = '/platform/fan-tray'
    logging.debug('Getting TOR fan information')
    fan_raw_data = run_gnmi_query(gnmi_host,args.username,args.password,args.hostname,gnmi_path)
    fan_status_parsed_data = parse_gnmi_result(fan_raw_data)
    fan_status = parse_fan_status(fan_status_parsed_data,args.hostname)


    #Run power supply checks
    gnmi_path = '/platform/power-supply'
    logging.debug('Getting TOR power supply information')
    power_supply_raw_data = run_gnmi_query(gnmi_host,args.username,args.password,args.hostname,gnmi_path)
    power_supply_parsed_data = parse_gnmi_result(power_supply_raw_data)
    power_supply_status = parse_power_supply_status(power_supply_parsed_data,args.hostname)

    #Run control card checks:
    gnmi_path = '/platform/control'
    logging.debug('Getting TOR CPM card information')
    control_raw_data  = run_gnmi_query(gnmi_host,args.username,args.password,args.hostname,gnmi_path)
    control_parsed_data = parse_gnmi_result(control_raw_data)
    control_status = parse_control_status(control_parsed_data,args.hostname)


    #Run line card checks:
    gnmi_path = '/platform/linecard'
    logging.debug('Getting TOR linecard information')
    linecard_raw_data  = run_gnmi_query(gnmi_host,args.username,args.password,args.hostname,gnmi_path)
    linecard_parsed_data = parse_gnmi_result(linecard_raw_data)
    linecard_status = parse_linecard_status(linecard_parsed_data,args.hostname) 

    #Get tunnel data
    gnmi_path = '/tunnel'
    logging.debug('Getting TOR tunnel information')
    tunnel_raw_data = run_gnmi_query(gnmi_host,args.username,args.password,args.hostname,gnmi_path)
    tunnel_parsed_data = parse_gnmi_result(tunnel_raw_data)
    tunnel_status  = parse_tunnel_information(tunnel_parsed_data,args.hostname)

    #Check for any bouncing ports
    logging.debug('Checking for bouncing ports')
    port_status = check_bouncing_ports(gnmi_host,args.username,args.password,args.hostname)
    report_port_issues(port_status,args.hostname)

    #Generate list of ports we will shutdown through GNMI to prepare for upgrade

    #This we handle outside of normal compare and save data because we want to know before an upgrade if happening as well. 
    if args.pre_check:
        logging.debug('User selected precheck option and gathering data')
        #Generate list of ports we will shutdown through GNMI to prepare for upgrade
        tor_access_ports_for_shutdown = generate_port_shutdown(interface_status,gnmi_host,args.username,args.password,args.hostname)
        save_data(tor_bgp_status,tor_version,tor_application_status,network_instance_status,interface_status,fan_status,power_supply_status,control_status,linecard_status,arp_status,mac_information_status,tunnel_status,port_status,tor_access_ports_for_shutdown,args.hostname,'precheck')
        enter_bgp_maint_mode(gnmi_host,args.username,args.password,args.hostname)
        shutdown_access_ports(tor_access_ports_for_shutdown,gnmi_host,args.username,args.password,args.hostname)
    if args.post_check:
        logging.debug('User selected post check option, comparing data')
        tor_access_ports_for_shutdown = [] #for now because this function needs something and we do not want to shutdown here, pass in a blank var
        save_data(tor_bgp_status,tor_version,tor_application_status,network_instance_status,interface_status,fan_status,power_supply_status,control_status,linecard_status,arp_status,mac_information_status,tunnel_status,port_status,tor_access_ports_for_shutdown,args.hostname,'postcheck')
        compare_data(args.hostname)
    
    logging.debug('End of script')

if __name__ == "__main__":
    main()