#!/usr/bin/env python3

"""i.py: Script que permite realizar una consulta a ifconfig.co extrayendo la dirección IP, 
Se hace uso de la funcion random para evitar que exista alguna limitante del servicio de ifconfig.co donde se realiza la consulta.

mypath: Directorio donde se encuentran los ficheros
jsonfolder_output: Directorio donde se tendra la salida de los .json para ser tratados
ipsfile: Listado de direcciones IP
servicestring: Servicio donde se consume las ips. 
"""

__author__      = "Jose Moruno Cadima, Lizbeth Leaños Jataco"
__copyright__   = "Copyright 2021 www.sniferl4bs.com"
__license__ = "CC BY-NC-SA 4.0"
__version__ = "0.1"
__email__ = "sniferl4bs@gmail.com"


import time, random, json, os, shodan
import requests as req
from os import listdir
from os.path import isfile, join
from pprint import pprint
from colorama import init, Fore, Back, Style

print(''' 
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
        
        ''')

# Mensajes 
info_execution=(Fore.RED + '[' + Fore.GREEN  + '+' +  Fore.RED + ']' +  Fore.WHITE + Style.BRIGHT + ' Obteniendo datos de las direcciones IP' + Style.RESET_ALL)

mypath='/Desktop/PoC/JSON/' 
jsonfolder_output=mypath +'JsonFiles/' 
ipsfile=mypath + 'lista.ip' 
servicestring='http://ifconfig.co/json?ip=' 
isps={}
shodan_api='XXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX'
api = shodan.Shodan(shodan_api)

# Lista de user agents
user_agent_list = [
    'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_5) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/13.1.1 Safari/605.1.15',
    'Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:77.0) Gecko/20100101 Firefox/77.0',
    'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_5) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/83.0.4103.97 Safari/537.36',
    'Mozilla/5.0 (Macintosh; Intel Mac OS X 10.15; rv:77.0) Gecko/20100101 Firefox/77.0',
    'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/83.0.4103.97 Safari/537.36',
]

print(info_execution)

#sitetor = req.get('https://check.torproject.org/exit-addresses')
sitetor = req.get('https://check.torproject.org/torbulkexitlist')
ips_tor=sitetor.text
print(Fore.RED + '[!] ' + Fore.GREEN  + 'Direcciones IP que son nodos de salida de TOR' + Style.RESET_ALL)
with open(ipsfile, 'r') as f_input:
    for line in f_input.readlines():
        time.sleep(random.random()*10)
        ip_line=line.rstrip("\n")
        user_agent = random.choice(user_agent_list)
        headers = {'User-Agent': user_agent}  
        jsonrequest = req.get(servicestring + ip_line,headers=headers)
        jsonfile = jsonfolder_output + ip_line+'.json'
        if os.path.exists(jsonfile): os.remove(jsonfile)
        with open(jsonfile, 'a') as f_output:
            f_output.write(jsonrequest.text)

        if ip_line in ips_tor :
          with open('nodes_tor.txt', 'a') as tor_output:
            tor_output.write(ip_line + '\n')
          print(ip_line + ' <-' + Fore.RED + '  True' + Style.RESET_ALL)
        else:
          print(ip_line + ' <- False') 


print('\n' + Fore.RED + '[+] ' + Fore.GREEN + 'Reporte de las direcciones IP analizadas' + Style.RESET_ALL )          


     
for f in listdir(jsonfolder_output):
    if isfile(join(jsonfolder_output,f)):
        file=(join(jsonfolder_output,f))
        with open(file) as json_file:
            try:                
                data = json.load(json_file)
                if 'ip' in data:
                    print( Fore.RED + 'IP: ' + Style.RESET_ALL + data['ip'])
                if 'country' in data:
                    print(Fore.RED + 'Pais: ' +  Style.RESET_ALL + data['country'])
                if 'asn_org' in data:
                    print(Fore.RED + 'ASN ORG: ' + Style.RESET_ALL + data['asn_org'])
                    if data['asn_org'] in isps:
                        isps[data['asn_org']]+=1
                    else:
                        isps[data['asn_org']]=1
                if 'hostname' in data:
                    print(Fore.RED + 'Hostname: ' + Style.RESET_ALL + data['hostname'])
            except Exception as e: 
                print('Fichero con error: ' + file)
            print('-----------')

# Shodan search for ports
print('\n-----------')
with open(ipsfile, 'r') as f_input:
    for line in f_input.readlines():
        try:
            line = line.replace('\n', '')
            result = api.host(line)
            print('Servicios encontrados en: ' + line)
            for port in result['ports']:
                print(Fore.GREEN + 'Puerto encontrado: ' + Style.RESET_ALL + str(port))
            print('-----------')
        except Exception:
            print(Fore.RED + 'No hay puertos disponibles para la IP ' + line + Style.RESET_ALL)
            print('-----------')
            
sorted_asn_org = sorted(isps.items(), key=lambda kv: kv[1])
print('\n' + Fore.RED + '[+] ' + Fore.GREEN + ' Cantidad de IPs por ASN: ' + Style.RESET_ALL )    
pprint(sorted_asn_org)

for isp in isps:
    isp_file=isp+'.txt'
    for f in listdir(jsonfolder_output):
        if isfile(join(jsonfolder_output,f)):
            file=(join(jsonfolder_output,f))
            #print(file)
            with open(isp_file, 'a') as f_output:
                with open(file) as json_file:
                    try:                
                        data = json.load(json_file)
                        if ('asn_org' in data):
                            if(data['asn_org']==isp):
                                f_output.write('ASN: ' + data['asn_org'] + ' ')
                                if 'ip' in data:
                                    f_output.write('IP: ' +data['ip'] + ' ')
                                if 'country' in data:
                                    f_output.write('Pais: ' +data['country']  + '\n')
                    except Exception as e:
                        pass 

print(Fore.RED + '\n ATENCIÓN:' + Style.RESET_ALL +''' 
  Las direcciones IP que son nodos de salida de TOR se encuentran en: nodes_tor.txt
  Se cuenta por cada ASN identificado un fichero .txt con la cantidad de IP que corresponden al mismo.''')

