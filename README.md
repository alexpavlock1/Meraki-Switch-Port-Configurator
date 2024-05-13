                                           Meraki API Switch Port Configurator
 
 

Prerequisites
-PIP - https://macpaw.com/how-to/install-pip-mac
For mac, in terminal run-
‘pip3 install meraki’
(this will install the meraki python library)
-Check your python version and ensure your running python version 3
python -V or python3 -V. If your not on python version 3 you can download here: https://www.python.org/downloads/mac-osx/ or use homebrew if you have it and run ‘brew install python’
-This program also relies on the batch_helper python module. This can be found here: https://github.com/TKIPisalegacycipher/Action-Batch-Helper. There is also a community post with a few videos explaining how the module works if interested- https://community.meraki.com/t5/Developers-APIs/New-tool-Action-Batch-Helper/m-p/128033. You will need to download the batch_helper from github and store the file in the same directory you are running this script from. From terminal you can run this command to download: git clone https://github.com/TKIPisalegacycipher/Action-Batch-Helper.git. Once downloaded move the files into the directory with this script.
 
 
 


The idea of this program is to be able to mass pushout Meraki MS and Meraki managed Catalyst switch port configurations. A common problem customers have is they are deploying out large quantities of switches and need to configure each switches port configurations. For the most part all access switches would have identical configurations along with distribution and core switches having the same configurations. Instead of going through each switch one by one and configuring each port one by one, or having to rely on port profiles or templates which introduce limitations why not create a script and be able to push out port configurations by the thousands in seconds? That is the catalyst for making this program.
 


This script relies on tags within dashboard. If you navigate to switching>switches you can filter the results of this page to show certain switches based on device name within dashboard, device model, current tags, online/offline. Using the example of rolling out 200 access switches for the most part these models will all be the same or use the same naming convention within dashboard so filter the list to show just our access switches. Once filtered use the check all button to select all switches. Now we can create our tag and assign it to all these devices. Click the tag button and either select an already created tag or type a name for a new tag and click save. If we don’t already have the tags column showing lets select the settings icon and enable this column and verify our switches have the tag we want.



 
The program is designed to have you choose if we are configuring link aggregations or port configs, enter your API key, select the organization, and select the network we are working with. Once we are in the correct network it will find all the active tags that exist and have you select the tag we are working with. Once you select the tag it will go find all the serial numbers of the switches that have that tag assigned to it. The script will show you the number of switches we have found so just verify that number is what is expected based on what you’ve tagged in dashboard. Once we have the serial’s we want to configure the script will go through all the port configuration options. It is recommended to copy and paste values directly from the prompts to avoid mistyping a configuration. After that it will send the configurations to dashboard and either return successful message or an error message with details and then return to the start of the program. This program utilizes action batches so thousands of port configurations can be sent easily and quickly.




 
 
