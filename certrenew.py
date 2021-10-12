import re
import requests
from requests.api import get
from requests.auth import HTTPBasicAuth
import json
import pprint
from socket import errorTab
import paramiko


# Read this article to find out more about managing the F5s certificates
# https://support.f5.com/csp/article/K15462
# Additionally note this very annoying quirk of the way F5 handles certs
# ==================================
# SSL certificates and keys are stored in the BIG-IP system's filestore directory. 
# The BIG-IP filestore adds a unique identifier to each SSL certificate and key file name. 
# For this reason, the SSL certificate and key filestore name will not be identical to the tmsh file name.
# ===================================

def F5_api_request(path,host,username,password):
    auth  = HTTPBasicAuth(username, password)
    url = 'https://{}/mgmt/tm/{}'.format(host,path)
    request = requests.get(url, verify=False, auth = auth )
    return json.loads(request.text)

#find different certificates:
def getCertsHash(host,username,password):
    certs = F5_api_request('sys/crypto/cert',host,username,password)
    return certs

#should really make this a better function at some point
def getCrypto(host,username,password):
   
    #set up ssh
    ssh_client_from=paramiko.SSHClient()
    ssh_client_from.set_missing_host_key_policy(paramiko.AutoAddPolicy())
    ssh_client_from.connect(hostname=host,username=username,password=password)

    #retrieve certs
    stdin,stdout,stderr=ssh_client_from.exec_command("grep '' /dev/null /config/filestore/files_d/Common_d/certificate_d/* | grep -v -E '(default|bundle|f5)'")
    crypto={}
    crypto['certs'] = {}
    crypto['certs']['all'] = (stdout.readlines())   
    err = (stderr.readlines())

    #dictify certs
    #lines being parsed will look something like this
    #/config/filestore/files_d/Common_d/certificate_d/:Common:testytest.crt_234361_1:KyqTgaLXeIVXDP0KPVx7ifJ5r/BMDnuPaqPkGRH9tt/6JHz1R2ebb4gbqFk=
    for line in crypto['certs']['all']:
        keyName = (re.findall(r':Common:\S+\.crt',line))[0].replace(':Common:','')
        if keyName not in crypto['certs']:
            crypto['certs'][keyName] = ''
        crypto['certs'][keyName]= crypto['certs'][keyName]+ (re.findall(r'[^:]+$',line))[0]
    
    #delete full certs list no longer required
    crypto['certs'].pop('all', None)

    #retrieve ssl keys
    crypto['keys'] = {}
    stdin,stdout,stderr=ssh_client_from.exec_command("grep '' /dev/null /config/filestore/files_d/Common_d/certificate_key_d/* | grep -v -E '(default|bundle|f5)'")
    print("grep '' /dev/null /config/filestore/files_d/Common_d/certificate_key_d/* | grep -v -E '(default|bundle|f5)'") 
    crypto['keys']['all'] = (stdout.readlines())
    err = (stderr.readlines())

    #dictify ssl keys
    #lines being parsed will look something like this
    #/config/filestore/files_d/Common_d/certificate_d/:Common:testytest.crt_234361_1:KyqTgaLXeIVXDP0KPVx7ifJ5r/BMDnuPaqPkGRH9tt/6JHz1R2ebb4gbqFk=
    
    for line in crypto['keys']['all']:
        keyName = (re.findall(r':Common:\S+\.key',line))[0].replace(':Common:','')
        if keyName not in crypto['keys']:
            crypto['keys'][keyName] = ''
        crypto['keys'][keyName]= crypto['keys'][keyName]+ (re.findall(r'[^:]+$',line))[0]

    #delete full certs list no longer required
    crypto['keys'].pop('all', None)

    ssh_client_from.close()
    return(crypto)

def uploadCrypto(hostIP,username,password,crypto):
    #target commands
    ssh_client_target=paramiko.SSHClient()
    ssh_client_target.set_missing_host_key_policy(paramiko.AutoAddPolicy())
    ssh_client_target.connect(hostname=hostIP,username=username,password=password)
    ftp = ssh_client_target.open_sftp()
    my_file = ftp.file('/var/tmp/'+ crypto[0], 'w') # 'w' will open the file for editing - it will truncate whatever was there before
    my_file.write(crypto[1]) # write whatever you wish to the file
    my_file.flush()
    ftp.close()

    if 'crt' in crypto[0]:
        stdin,stdout,stderr=ssh_client_target.exec_command("tmsh install sys crypto cert {} from-local-file /var/tmp/{}".format('autotest123',crypto[0]))
    else:
        stdin,stdout,stderr=ssh_client_target.exec_command("tmsh install sys crypto key {} from-local-file /var/tmp/{}".format('autotest123',crypto[0]))
    print(stdout.readlines())
    print(stderr.readlines())
    stdin,stdout,stderr=ssh_client_target.exec_command('rm /var/tmp/'+ crypto[0])
    print(stdout.readlines())
    print(stderr.readlines())
    ssh_client_target.close()

priCerts = getCertsHash('192.168.1.100','admin','admin')
secCerts = getCertsHash('192.168.1.100','admin','admin')

# priCrypto = getCrypto('192.168.1.100','root','default')
# secCrypto = getCrypto('192.168.1.100','root','default')
#
#
#
##for the sake of testing fake delete a cert
#del secCrypto['certs']['testytest_20210907.crt']
#del secCrypto['keys']['testytest_20210907.key']
#
##initalise list of items to be replicated
#replicationItems=[]
#
##get certs from primary
#cryptoNames = []
#for name in priCrypto['certs'].keys():
#    cryptoNames.append(name)
#    print(name)
#]
#
#
## for certs on primary
#for name in cryptoNames:
#    #if cert on other device
#    if name in secCrypto['certs']:
#        #if cert text is not the same
#        if not priCrypto['certs'][name] == secCrypto['certs'][name]:
#            #add cert to items to be replicated
#            replicationItems.append((name,priCrypto['certs'][name]))
#
#    #if cert is not on the other device then replicate
#    else:
#         replicationItems.append((name,priCrypto['certs'][name]))
#
#    #if there is a key for that cert on primary
#    if name in priCrypto['keys']:
#        # if that key doesnt exist in secondary replicate it
#        if name not in secCrypto['keys'][name]:
#             replicationItems.append((name,priCrypto['keys'][name]))
#        #else if the values dont match then replicate
#        elif not priCrypto['keys'][name] == secCrypto['keys'][name]:
#            replicationItems.append(priCrypto['keys'][name])
#
#pprint.pprint(replicationItems)
#
##for item in replicationItems:
##    uploadCrypto('192.168.1.100','root','default', item)
#
##var: { 
##    certs: {
##        cert 1: 'cert text',
##        cert 2: 'cert text'
##        }
##    },
##    keys : {
##       same format as certs
##    }
##}