# gnmi-testing

## Parameters for script

-tor_ip
-username
-hostname
-password
-pre_check True  - if running before upgrade. This will gather data, and also ask a few questions about shutting down access ports and bgp maint mode
-post_check True - if running after upgrade. Can run before access ports are brought up to check underlay, and also another final post verification after ports are enabled. 
-no_shut_ports - this will enable any ports that were up and operational (but not in the default network instance) that were found to be up before hand in the prechecks

## Running script

Before the TOR is upgraded, run the script first to gather data. This will make a folder named "TOR-Hostname-Before" and several .json files within
Ex:
python3 srl_upgrade.py -tor_ip 10.24.250.79 -username admin -password admin -hostname tor_hostname -pre_check True

After the TOR is upgraded, run the script again to gather the data then compare. This will make a folder named "TOR-Hostname-After" and several .json files within
python3 srl_upgrade.py -tor_ip 10.24.250.79 -username admin -password admin -hostname tor_hostname -post_check True