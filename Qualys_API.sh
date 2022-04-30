#!/bin/bash

#./Qualys_API.sh USERNAME PASSWORD Intern+Scan+-+17 IP_Addr
clear
echo " "
echo "$(tput setaf 3)[+] $(tput setaf 2) ####################################################"
echo "$(tput setaf 3)[+] $(tput setaf 2) # Script   : Qualys_API.sh				#"
echo "$(tput setaf 3)[+] $(tput setaf 2) # Function : Vulnerability Scanner - Qualys API	#"
echo "$(tput setaf 3)[+] $(tput setaf 2) # Coded by : Shubham Tandlekar			#"
echo "$(tput setaf 3)[+] $(tput setaf 2) ####################################################"
echo " "
echo " "


## ensure that the given arguments are correct
if [[ $# -ne 4 ]]; then
	echo "usage: $0 username password scan_title ip_addr" >&2
	echo " "
	exit 1
fi

sleep 2
echo "$(tput setaf 3)[+] $(tput setaf 2) Starting the Qualys API"
echo " "
echo "$(tput setaf 3)[+] $(tput setaf 2) Setting the URL, USERNAME AND PASSWORD."
echo " "


#Setting up the script environments
url="https://qualysapi.qg2.apps.qualys.com"
username=$1
password=$2
scan_title=$3
ip_addr=$4

echo "$(tput setaf 3)[+] $(tput setaf 2) Generating the Session ID"
echo " "

#Generating Session ID
curl -H "X-Requested-With: Curl Sample" -D headers --dump-header "Session_ID" -d "action=login&username=$username&password=$password" "$url/api/2.0/fo/session/" &>/dev/null


#Setting the Session ID in the Session_ID Variable
Session_ID=$(cat Session_ID | grep 'QualysSession' | cut -d '=' -f 2 | cut -d " " -f 1 | cut -d ';' -f 1)

echo "$(tput setaf 3)[+] $(tput setaf 2) Sending the Curl Request"
echo " "


echo " "
echo "$(tput setaf 3)[+] $(tput setaf 2) #### ----RAW OUTPUT START---- ####"
echo " "


#Actually Luanching the Scan
curl -H "X-Requested-With: Curl Sample" -b "QualysSession=$Session_ID; path=/api; secure" -d "action=launch&scan_title=$scan_title&target_from=assets&ip=$ip_addr&asset_groups=Shubham+-+Test+IP+Range&exclude_ip_per_scan=10.10.10.10&iscanner_name=NameOfTheScanner&option_title=CPE+Curated+Port+List&priority=2" "$url/api/2.0/fo/scan/" -o "Scan_launched.txt"


#Extracting the Scan Ref
cat Scan_launched.txt | grep 'scan/' | cut -d '>' -f 2 | cut -d '<' -f 1 > "Scan_Ref.txt"
scan_ref=$(cat Scan_Ref.txt)


echo " "
echo "$(tput setaf 3)[+] $(tput setaf 2) #### ----RAW OUTPUT END---- ####"
echo " "

echo " "
echo "$(tput setaf 3)[+] $(tput setaf 2) Waiting ~14 mins ( Based on Experimental Values )"
sleep 900
echo " "

echo "$(tput setaf 3)[+] $(tput setaf 2) Downloading the Report"
echo " "


#Saving the results in CSV file
curl -H "X-Requested-With: Curl Sample" -b "QualysSession=$Session_ID; path=/api; secure" -d "action=fetch&echo_request=1&output_format=csv&scan_ref=$scan_ref" "$url/api/2.0/fo/scan/" -o "results.csv"


echo " "
echo "$(tput setaf 3)[+] $(tput setaf 2) Logging out from the session"
echo " "

#Sending a request to Log out
curl -H "X-Requested-With: Curl Sample" -b "QualysSession=$Session_ID; path=/api; secure" -d "action=logout" "$url/api/2.0/fo/session/" &>/dev/null


echo " "
echo "$(tput setaf 3)[+] $(tput setaf 2) Cleaning the mess"
echo " "
rm -rf Session_ID
rm -rf Scan_launched.txt
rm -rf Scan_Ref.txt
rm -rf status
rm -rf result.txt
