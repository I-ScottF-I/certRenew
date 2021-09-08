How this works at a high level:

This script would be exectued in the time window between sensor renewal and replication script

Problems:
    if cert and key are assosciated with more than one SSL profile may be conflicts during replication
    similar named certs may be replicated
    host may be down and this is not handled

####################

define function F5_get_request which takes a path, host ip and returns the response payload of an API request to that url
define function copyCrypto which scp's a cert and key assosciated with a cert, records c-ssl config and attached vips
define function importCrypto which takes certs in /var/tmp, installs them, creates c-ssl config

set host list and their DR counterpart in a list of dicts (active host ip, dr host ip)
set todays date

for host in activehostlist (the list of hosts that are monitored by sensor):
    F5_get_request for all client-ssl profiles on the host
    F5_get_request for all client-ssl profiles on the DR host
    for profile in client-ssl profiles on PRIMARY host:
        if client-ssl profile was renewed today(TBD maybe extend to last week) and corresponding profile doesnt exist on DR host:
            copyCrypto on old device
            importCrypto on new device
            for every vip:
                if uses old cssl profile
                    replace old client ssl profile with new one                        