#!/bin/bash

#
# Author: "Jose Moruno Cadima"
# Copyright: "Copyright 2021 www.sniferl4bs.com"
# License: "CC BY-NC-SA 4.0"
# Version: "0.1"
# Email: "sniferl4bs@gmail.com"
#

echo "
                \||/
                |  @___oo    ____   _   _____   _____ 
      /\  /\   / (__,,,,|   |  __| | | |  _  | |  _  |
     ) /^\) ^\/ _)          | |_   | | | |_| | | | | |
     )   /^\/   _)          |  _|  | | |  ___| | | | |
     )   _ /  / _)          | |__  | | | |     | |_| |
 /\  )/\/ ||  | )_)         |____| |_| |_|     |_____|
<  >      |(,,) )__)
 ||      /    \)___)\       Easy IP Osint
 | \____(      )___) )___
  \______(_______;;; __;;;  www.sniferl4bs.com 
"

  for i in $(cat $1); do curl -sS ifconfig.co/json\?ip=$i -o $i.json; sleep 5; done
echo "Consultando las direcciones IP..."

echo "IP             ASN ORG       COUNTRY    
===            =======       ========         "
jq -r '[.ip, .contry_iso, .asn_org, .country ] | @tsv' *.json | column -ts $'\t' | tee report.txt
tput setaf 1; echo -e "[+]$(tput sgr0) Cantidad de IP's Paises "

jq -r '.country' *.json | sort | uniq -c 

tput setaf 1;echo  "[+]$(tput sgr0) Cantidad de IP's ASN"

jq -r '.asn_org' *.json | sort | uniq -c 


tput setaf 1; echo "[+]$(tput sgr0) Direcciones IP que son nodos de salida de TOR"; tput sgr0
rm torbulkexitlist 2>/dev/null
curl -sS https://check.torproject.org/torbulkexitlist -o torbulkexitlist
grep -F -f torbulkexitlist $1 | tee nodes_tor.list 



