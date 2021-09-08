import requests
import re
import paramiko
import json
import datetime
import urllib3
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

now = datetime.datetime.now()
datestring=(now.strftime('%Y%m%d'))

hosts = [
    {'PRI_hostname': 'F5VM','PRI_ip': '192.168.1.100','DR_hostname': 'F5VM','DR_IP': '192.168.1.100',}
]

# make A GET for the requested path and respond with a dictonary of the response payload
def F5_get_request(path, hostip):
    url = 'https://{}/mgmt/tm/{}'.format(hostip,path)
    auth = ('admin','admin')
    request = requests.get(url, verify=False, auth=auth)
    response = json.loads(request.text)
    return response

def F5_patch_request(path, hostip, profiles):
    url = 'https://{}/mgmt/tm/{}'.format(hostip,path)
    auth = ('admin','admin')
    payload = json.dumps(profiles)
    print(payload)
    request = requests.patch(url, verify=False, auth=auth, data=payload)
    response = json.loads(request.text)
    return response

def exportCrypto(host,username,password,certName,keyName,csslProfileName):
    ssh_client_from=paramiko.SSHClient()
    ssh_client_from.set_missing_host_key_policy(paramiko.AutoAddPolicy())
    ssh_client_from.connect(hostname=host['PRI_ip'],username=username,password=password)
    stdin,stdout,stderr=ssh_client_from.exec_command("scp /config/filestore/files_d/Common_d/certificate_d/:Common:{}* {}@{}:/var/tmp".format(certName, username, host['DR_IP'] ))
    print("scp /config/filestore/files_d/Common_d/certificate_key_d/:Common:{}* {}@{}:/var/tmp".format(certName, username, host['DR_IP'] ))
    print(stdout.readlines())
    print(stderr.readlines())
    stdin,stdout,stderr=ssh_client_from.exec_command("scp /config/filestore/files_d/Common_d/certificate_key_d/:Common:{}* {}@{}:/var/tmp".format(keyName, username, host['DR_IP']))
    print("scp /config/filestore/files_d/Common_d/certificate_d/:Common:{}* {}@{}:/var/tmp".format(keyName, username, host['DR_IP']))
    print(stdout.readlines())
    print(stderr.readlines())
    stdin,stdout,stderr=ssh_client_from.exec_command("tmsh list ltm profile client-ssl {} one-line".format(csslProfileName))
    profile_config = stdout.readlines()[0].replace('\n','')
    print('tmsh list ltm profile client-ssl {} one-line'.format(csslProfileName))
    print(stdout.readlines())
    print(stderr.readlines())
    ssh_client_from.close()
    return profile_config

def importCrypto(profile_config,hostIP,username,password,certName,keyName):
    #target commands
    ssh_client_target=paramiko.SSHClient()
    ssh_client_target.set_missing_host_key_policy(paramiko.AutoAddPolicy())
    ssh_client_target.connect(hostname=hostIP,username=username,password=password)
    stdin,stdout,stderr=ssh_client_target.exec_command("tmsh install sys crypto cert 3{} from-local-file /var/tmp/:Common:{}*".format(certName,certName))
    print("tmsh install sys crypto cert 3{} from-local-file /var/tmp/:Common:{}*".format(certName,certName))
    print(stdout.readlines())
    print(stderr.readlines())
    stdin,stdout,stderr=ssh_client_target.exec_command("tmsh install sys crypto key 3{} from-local-file /var/tmp/:Common:{}*".format(keyName,keyName))
    print("tmsh install sys crypto key 3{} from-local-file /var/tmp/:Common:{}*".format(keyName,keyName))
    print(stdout.readlines())
    print(stderr.readlines())
    #modify the config from new profile so it will fit on fake pair
    profile_config = profile_config.replace('20210908','REPLACE')
    profile_config = profile_config.replace('testSubject.','3testSubject.')
    #these are required for all ssl certs (need to make sure there is no collateral damage)
    profile_config = profile_config.replace('cert-key-chain {','cert-key-chain add {')
    profile_config = re.sub(r'[^\s]+ false','',profile_config) 
    print(profile_config)

    stdin,stdout,stderr=ssh_client_target.exec_command('tmsh create ' + profile_config)
    print('tmsh create ' + profile_config)
    print(stdout.readlines())
    print(stderr.readlines())
    ssh_client_target.close()

#PERFORM LOGIC TO DECIDE WHICH CERTS NEED RENEWED
needsReplaced = False
for host in hosts:
    sslProfilesPri = F5_get_request('ltm/profile/client-ssl',host['PRI_ip'])
    sslProfilesDR = F5_get_request('ltm/profile/client-ssl',host['DR_IP'])
    vipDR =  F5_get_request('ltm/virtual?expandSubcollections=true',host['DR_IP'])
    for sslProfile in sslProfilesPri['items']:
        if datestring in sslProfile['name']:
            cert = sslProfile['certKeyChain'][0]['cert'].replace('/Common/','')
            key = sslProfile['certKeyChain'][0]['key'].replace('/Common/','')
            config = exportCrypto(host,'root','default',cert,key,sslProfile['name'])
            importCrypto(config,host['PRI_ip'],'root','default',cert,key)
            for vip in vipDR['items']:
                if 'profilesReference' in vip:
                    payloadProfiles = []
                    for profile in vip['profilesReference']['items']:
                        if sslProfile['name'] in profile['name']:
                            print('match on vip'+vip['name'])
                            payloadProfiles.append('/Common/clientSSL_REPLACE')
                            needsReplaced = True
                        else:
                            payloadProfiles.append(profile['fullPath'])
                    if needsReplaced:
                        payload = {'profiles': payloadProfiles}
                        print(payload)
                        output = F5_patch_request('ltm/virtual/~Common~'+vip['name'],host['DR_IP'],payload)
                        print(output)
                        needsReplaced = False