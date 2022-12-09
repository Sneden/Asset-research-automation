#Remember to connect to SAP vpn to get 6connect working

import json
import os
import random
from datetime import date, datetime
from os import scandir

import pandas as pd
import requests
from bs4 import BeautifulSoup
from lxml import etree
from requests.auth import HTTPBasicAuth
from shodan import Shodan

Shodan_api = Shodan('<ShodanAPI_KEY>')
Tenable_api = "<TenableAPI_KEY>"
username = '<6connect_username>'
password = '<6connect_password>'
df = pd.read_csv('<Input_file_location.csv>') #list of IP's in one column
length = len(df)
count = 0
df_csv = pd.DataFrame()
df_new = pd.DataFrame()
for index, row in df.iterrows():
    try: 
        ip = row["ip"]
        count = count + 1
        print(str(count) + "  of  " + str(length) + "  -  " + ip)
       
            # --------------SHODAN.IO--------------#
        try:
            #print("\n\n\n#-------------SHODAN.IO-------------#\n\n\n")
            host = Shodan_api.host(ip)

            # Print general info
            general = ("""
                    IP: {}
                    ISP: {}
                    Organization: {}
                    Operating System: {}
            """.format(host['ip_str'], host.get('isp','n/a'), host.get('org', 'n/a'), host.get('os', 'n/a')))

            # Print all banners
            for item in host['data']:
                    info = ("""
                            Hostname: {}
                            Domain: {}
                            Port: {}
                            Banner: {}
                    """.format(item['hostnames'] , item['domains'], item['port'], item['data']))
            shodan_data = general+info
        
        except:
            shodan_data = "Null"
            pass
    
    
    
        #------------TENABLE.IO ASSETS-----------#
        try:
            #print("\n\n\n#-------------TENABLE.IO ASSETS-------------#\n\n\n")
            url = 'https://cloud.tenable.com/workbenches/assets?date_range=30&filter.0.filter=host.target&filter.0.quality=match&filter.0.value=%s&filter.search_type=and'%(ip)

            headers = {
                "accept": "application/json",
                "X-ApiKeys": Tenable_api
            }

            response_uuid = requests.get(url, headers=headers)

            # get asset uuid
            uuid_data = json.loads(response_uuid.text)
            uuid = uuid_data["assets"][0]["id"]

            # get asset info from uuid
            url = "https://cloud.tenable.com/assets/%s"%(uuid)
            headers = {
                "accept": "application/json",
                "X-ApiKeys": Tenable_api
            }
            response_asset = requests.get(url, headers=headers)
            asset_data = json.loads(response_asset.text)
            tenable_data = json.dumps(asset_data, indent=6)

        except:
            tenable_data = "Null"
            pass
        
        
        #-------------6 connect-------------#
        try:
            #print("\n\n\n#-------------6 connect-------------#\n\n\n")
            run="aggregate"
            endpoint = "https://acp.corereg.only.sap/api/v1/projects/lookup-single-ip/execute"
            post_body = json.dumps({
                        "ip": ip, 
                        "raw-data": 0,
                });
            headers = {'Content-Type': 'application/json'}
            auth = requests.auth.HTTPBasicAuth(username, password)
            try:
                r = requests.post(endpoint, data=post_body, headers=headers, auth=auth, verify=False)
            except requests.ConnectionError as err:
                print("Error executing connect-to-ProVision request.")
                print(err)
                os._exit(1)

            json_data=r.json()
            connect_data =json.dumps(json_data, indent=2)

        except:
            connect_data = "Null"
            pass
        


        #-------------EXTERNAL WHOIS-------------#
        try:
            def GET_UA():
                uastrings = ["Mozilla/5.0 (Windows NT 6.1; WOW64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/38.0.2125.111 Safari/537.36",\
                    "Mozilla/5.0 (Windows NT 6.1; WOW64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/28.0.1500.72 Safari/537.36",\
                    "Mozilla/5.0 (Windows NT 6.1; WOW64; rv:33.0) Gecko/20100101 Firefox/33.0",\
                    "Mozilla/5.0 (Windows NT 6.3; WOW64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/38.0.2125.111 Safari/537.36",\
                    "Mozilla/5.0 (Windows NT 6.1; WOW64; Trident/7.0; rv:11.0) like Gecko",\
                    "Mozilla/5.0 (Windows NT 6.3; WOW64; rv:33.0) Gecko/20100101 Firefox/33.0",\
                    "Mozilla/5.0 (Windows NT 6.1; WOW64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/38.0.2125.104 Safari/537.36"\
                        ]
                return random.choice(uastrings)
    
            headers = {'User-Agent': GET_UA()}
            content = None
            #print("\n\n\n#-------------EXTERNAL WHOIS-------------#\n\n\n")
            ex_whois_url = 'https://who.is/whois-ip/ip-address/%s'%ip
            #ex_whois_url = 'https://dnschecker.org/ip-whois-lookup.php?query=%s'%ip
            r = requests.get(ex_whois_url, headers=headers)
            soup = BeautifulSoup(r.content, 'html.parser')
            s = soup.find("div", class_="col-md-12 queryResponseBodyKey").find_next(text=True)
            Extwhois_data = s
        
        except:
            Extwhois_data = "Null"
            pass

        #------------------Dataframe---------------#
        
        data = {'IP Address': [ip],
                'Tenable.io assets': [tenable_data],
                '6connect' : [connect_data],
                'External Whois' : [Extwhois_data],
                'Shodan.io': [shodan_data]
                }
                
        del df_new
        df_new = pd.DataFrame(data, columns=['IP Address','Tenable.io assets','6connect','External Whois','Shodan.io'])
        res = [df_csv, df_new]
        df_csv = pd.concat(res)
        cf = df_csv
        
        ef = pd.read_excel('<Append_to_file_location.xlsx>')
        frames = [ef, cf]
        research = pd.concat(frames)
        research = research.drop_duplicates(subset=['IP Address'])
        research.to_excel('<Append_to_file_location.xlsx>', index = False) #removes duplicate data in the same file.
        
    except: 
        print("\n Error in" + " - " + ip + "\n")
        pass
    
print("Done")


#----------------------------------------SAP domains -------------------------#

#-------------WHOIS-------------#
'''
whois_url = 'https://whois.global.cloud.sap/v1/query?input=%s'%(ip)
form_data = {'username': '', 'pass': pass} 
with requests.Session() as sesh:
    sesh.post(whois_url, data=form_data)
    response = sesh.get('https://whois.global.cloud.sap')
    html = response.text

soup = BeautifulSoup(response.content, 'html.parser')
print(soup.prettify()) 


#auth = (requests.auth.HTTPBasicAuth('sneden.rebello@sap.com', pass))
whois_url = 'https://whois.global.cloud.sap/v1/query?input=%s'%(ip)
auth = requests.auth.HTTPBasicAuth('6c-acp-technical-user_SGS-01', 'fvWH3vtPjUWzbNd%kg')
r = requests.post(whois_url, auth=auth, verify=True)
r = requests.get(whois_url, auth=auth)# verify=False)
print(r.content)
'''


#-------------SISM-------------#
'''
#sism_url = 'https://cmp.wdf.sap.corp/sesi/main/#/Search/%s' %(ip)
auth = (requests.auth.HTTPBasicAuth('', pass))
r = requests.get(sism_url, auth=auth) #verify=False)
print(r)


'''
#-------------LB tool-------------#
'''
url ='https://netsec-lbportal.wdf.sap.corp/lbportal/cgi-bin/lbportal_search.pl?source=Virt.+Service+130.264.191.93%2C+Port+443&detail_se=1396655'
resp=requests.get(url, verify=certServer)
soup = BeautifulSoup(resp.content, 'html.parser')
print(soup.prettify())
'''

