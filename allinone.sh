#!/bin/sh
########
#LICENSE                                                   
########

# Shell script for testing various server side vulnerabilities. VERSION 0.1a 
# Copyright (C) 2020-Future Aman Kumar                                   
#                                                                                                       
# This shell script is free software: you can redistribute it and/or modify                             
# it under the terms of the GNU General Public License as published by                                   
# the Free Software Foundation, either version 2 of the License, or                                     
# any later version.                                                                   
#                                                                                                       
# This program is distributed in the hope that it will be useful,                                       
# but WITHOUT ANY WARRANTY; without even the implied warranty of                                        
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the                                         
# GNU General Public License for more details.                                                          
#                                                                                                       
# You should have received a copy of the GNU General Public License                                     
# along with this shell script.  If not, see <http://www.gnu.org/licenses/>.
filename=$1
while read line; do

echo "--------------------------"
echo "           _____ __       "
echo "     /\   |_   _/_ |      "
echo "    /  \    | |  | |      "
echo "   / /\ \   | |  | |      "
echo "  / ____ \ _| |_ | |      "
echo " /_/    \_\_____||_|v0.1a "
echo "           -By Aman Kumar "
echo "--------------------------"
        echo "X------------------------------------------------------X"
        echo "|Subdomain Enumeration Using Assetfinder               |"
        echo "X------------------------------------------------------X"
        assetfinder --subs-only $line | tee -a $line.txt
        echo "X------------------------------------------------------X"
        echo "|Checking Possible Subdomain Takeover Using Subzy      |"
        echo "X------------------------------------------------------X"
        subzy -targets $line.txt -concurrency 100 -hide_fails | grep 'VULNERABLE'
        echo "X------------------------------------------------------X"
        echo "|Checking Possible Subdomain Takeover Using SubJack    |"
        echo "X------------------------------------------------------X"
        subjack -w $line.txt -t 100 -timeout 30 -o results.txt -ssl -c /home/kali/Desktop/gitProject/fingerprints.json
        echo "X------------------------------------------------------X"
        echo "|Checking Possible Subdomain Takeover Using SubOver    |"
        echo "X------------------------------------------------------X"
        SubOver -l $line.txt
        echo "X------------------------------------------------------X"
        echo "|Checking For HTTP Strict Transport Security Using Curl|"
        echo "X------------------------------------------------------X"
        curl -s -D- https://$line/ | grep -i Strict
        echo "X------------------------------------------------------X"
        echo "|Checking For Open-Redirects Using Waybackurls         |"
        echo "X------------------------------------------------------X"
        waybackurls $line | grep -a -i \=http | qsreplace 'http://evil.com' | while read host do;do curl -s -L $host -I | grep "evil.com" && echo "$host Vulnerable" ;done
        echo "X------------------------------------------------------X"
        echo "|Checking For Server-Side Vulnerabilities              |"
        echo "X------------------------------------------------------X"
        sudo bash testssl.sh $line | grep 'Start\|rDNS\|SSLv2\|SSLv3\|Obsolete\|OCSP\|Strict\|Heartbleed\|CCS\|Ticketbleed\|ROBOT\|Secure\|CRIME\|BREACH\|POODLE\|TLS_FALLBACK_SCSV\|SWEET32\|FREAK\|DROWN\|LOGJAM\|BEAST\|LUCKY13\|RC4'
        echo "X------------------------------------------------------X"
        echo "|Checking For DNS Zone Transfer Vulnerability          |"
        echo "X------------------------------------------------------X"
        sudo bash DNSaxfr.sh -r0 $line
        echo "X------------------------------------------------------X"
        echo "|Checking For Possible Parameter For Reflected XSS     |"
        echo "X------------------------------------------------------X"
        waybackurls $line | kxss | sed 's/=.*/=/'
done < $filename
#./automate.sh subs.txt
