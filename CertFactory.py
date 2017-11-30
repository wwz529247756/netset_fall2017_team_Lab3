'''
Created on 2017年11月1日

@author: wangweizhou
'''
from playground.network.packet.fieldtypes import UINT32, STRING, BUFFER,BOOL,LIST

privatekeyaddr = "/Users/wangweizhou/Desktop/public&private_key/host/Dumplinghostprivate.pem"
hostmediacert = "/Users/wangweizhou/Desktop/public&private_key/host/Dumplinghostcert.cert"
rootaddr = "/Users/wangweizhou/Desktop/public&private_key/root/root.crt"
intermidiacertaddr = "/Users/wangweizhou/Desktop/public&private_key/intermedia/DumplingCertificate.cert"


def getPrivateKeyForAddr(addr):
    if addr == "20174.1.12321.666":
        privatekeyaddr = "/Users/wangweizhou/Desktop/public&private_key/host/Dumplinghostprivate.pem"
        with open(privatekeyaddr) as f:
            Private_key = f.read()
        return Private_key



def getCertificateForAddr(addr):
    if addr == "20174.1.12321.666":
        hostmediacert = "/Users/wangweizhou/Desktop/public&private_key/host/Dumplinghostcert.cert"
        intermidiacertaddr = "/Users/wangweizhou/Desktop/public&private_key/intermedia/DumplingCertificate.cert"
        ClientCert=LIST(BUFFER)
        with open(hostmediacert) as f:
            Certificate0 = f.read()
        ClientCert.append(Certificate0.encode())
        
        with open(intermidiacertaddr) as f:
            Certificate1 = f.read()
        ClientCert.append(Certificate1.encode())
        
        return ClientCert
        
        

def getRootCert(addr):
    with open(addr) as f:
        RootCert = f.read()
    return RootCert

if __name__=='__main__':
    private_key = getPrivateKeyForAddr("/Users/wangweizhou/Desktop/public&private_key/Server/key.pem")
    public_key = getCertificateForAddr("/Users/wangweizhou/Desktop/public&private_key/Server/certificate.pem")
    print(public_key)
    