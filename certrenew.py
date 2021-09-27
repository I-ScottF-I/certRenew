import re
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

#should really make this a better function at some point
def getCrypto(host,username,password):
   
    #set up ssh
    ssh_client_from=paramiko.SSHClient()
    ssh_client_from.set_missing_host_key_policy(paramiko.AutoAddPolicy())
    ssh_client_from.connect(hostname=host,username=username,password=password)

    #retrieve certs
    stdin,stdout,stderr=ssh_client_from.exec_command("grep '' /dev/null /config/filestore/files_d/Common_d/certificate_d/* | grep -v -E '(default|bundle|f5)'")
    print("grep '' /dev/null /config/filestore/files_d/Common_d/certificate_d/* | grep -v -E '(default|bundle|f5)'") 
    crypto={}
    crypto['certs'] = {}
    crypto['certs']['all'] = (stdout.readlines())   
    err = (stderr.readlines())

    #dictify certs
    #lines being parsed will look something like this
    #/config/filestore/files_d/Common_d/certificate_d/:Common:testytest.crt_234361_1:KyqTgaLXeIVXDP0KPVx7ifJ5r/BMDnuPaqPkGRH9tt/6JHz1R2ebb4gbqFk=
    for line in crypto['certs']['all']:
        keyName = (re.findall(r':Common:[^:]+',line))[0]
        if keyName not in crypto['certs']:
            crypto['certs'][keyName] = {}
            crypto['certs'][keyName]['shortname'] = (re.findall(r':Common:\S+\.crt',line))[0]
            crypto['certs'][keyName]['certText'] = ''
        crypto['certs'][keyName]['certText'] = crypto['certs'][keyName]['certText'] + (re.findall(r'[^:]+$',line))[0]
    
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
        keyName = (re.findall(r':Common:[^:]+',line))[0]
        if keyName not in crypto['keys']:
            crypto['keys'][keyName] = {}
            crypto['keys'][keyName]['shortname'] = (re.findall(r':Common:\S+\.key',line))[0]
            crypto['keys'][keyName]['keyText'] = ''
        crypto['keys'][keyName]['keyText'] = crypto['keys'][keyName]['keyText'] + (re.findall(r'[^:]+$',line))[0]
        

    #delete full certs list no longer required
    crypto['keys'].pop('all', None)

    ssh_client_from.close()
    return(crypto)


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

priCrypto = getCrypto('192.168.1.100','root','default')
pprint.pprint(priCrypto)
#secCrypto = getCrypto('192.168.1.100','root','default')

#var { 
#    certs {
#        cert 1{
#            certShortName : 'name'
#            keyText : 'cert text'
#        },
#        cert 2 {
#            certShortName : 'name'
#            certText : 'cert text'
#        }
#    },
#    keys {
#       same format as certs
#    }
#}

for key in priCrypto['certs'].keys():
    #this will fail as 
    print(key.items())
    #if cert['shortname'] in secCrypto['certs']:
    #    print('cert {} exists in both DCs'.format(cert['shortname']))