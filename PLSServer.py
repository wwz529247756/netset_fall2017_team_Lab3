'''
Created on 2017年9月28日

@author: wangweizhou
'''
from playground.network.packet.fieldtypes import UINT32, STRING, BUFFER,BOOL,LIST
from playground.network.packet import PacketType
from playground.network.common import StackingProtocol
from playground.network.common import StackingProtocolFactory
from playground.network.common import StackingTransport
from CertFactory import *
import playground
from asyncio import *
import random
from PLSPackets import *
from Crypto.Signature import PKCS1_v1_5
from Crypto.PublicKey import RSA
import hashlib


#import playground.crypto


class PLSServer(Protocol):
    def __init__(self):
        self.privatekeyaddr = "/Users/wangweizhou/Desktop/public&private_key/Server/key.pem"
        self.certificateaddr = "/Users/wangweizhou/Desktop/public&private_key/Server/certificate.pem"
        self.transport = None
        self.ClientNonce = None
        self.ServerNonce = random.randint(10000,99999)
        self.deserializer = BasePacketType.Deserializer()
        self.rawKey = getPrivateKeyForAddr(self.privatekeyaddr)
        self.privateKey = RSA.importKey(self.rawKey)
        self.ServerCertificate = getCertificateForAddr(self.certificateaddr)
        self.ServerCert=LIST(BUFFER)
        self.ServerCert.append(self.ServerCertificate.encode())
        self.ClientCert=LIST(BUFFER)
        self.PacketList = []
        
    def connection_made(self,transport):
        self.transport=transport
        
        
    def data_received(self,data):
        self.data = data
        self.deserializer.update(data)
        for pkt in self.deserializer.nextPackets():
            self.PacketList.append(pkt)
            if isinstance(pkt, PlsHello):
                print("Hellopacket receive!")
                self.ClientNonce = pkt.Nonce
                self.ClientCert = pkt.Certs
                self.ClientCertificate = self.ClientCert[0].decode()
                #self.ClientPublickey = RSA.importKey(self.ClientCertificate)   #Client Public Key
                HelloPacket = PlsHello()
                HelloPacket.Nonce = self.ServerNonce
                HelloPacket.Certs = self.ServerCert
                self.transport.write(HelloPacket.__serialize__())
                self.PacketList.append(HelloPacket)
                #print(self.ClientCertificate)
                
            if isinstance(pkt, PlsKeyExchange):
                print("PlsKeyExchange receive!")
                self.PacketList.append(pkt)
                '''
                    Decrypt pkt.PreKey here!
                '''
                self.ClientPrekey = pkt.PreKey
                KeyExchangePacket = PlsKeyExchange()
                self.ServerPrekey = b"Need to be encrypted!"
                '''
                    Encrypt self.ServerPrekey here!
                '''
                KeyExchangePacket.PreKey = self.ServerPrekey
                KeyExchangePacket.NoncePlusOne = self.ClientNonce+1
                self.transport.write(KeyExchangePacket.__serialize__())
                print("KeyExchange sent!")
                self.PacketList.append(KeyExchangePacket)
                
            if isinstance(pkt, PlsHandshakeDone):
                print("PlsHandshakeDone receive!")
                self.validation =b''
                for packet in self.PacketList:
                    pktdata = packet.__serialize__()
                    self.validation = self.validation+pktdata
                self.hashvalidation = hashlib.sha1(self.validation).hexdigest()
                HandshakeDonePacket = PlsHandshakeDone()
                HandshakeDonePacket.ValidationHash = self.hashvalidation.encode()
                self.transport.write(HandshakeDonePacket.__serialize__())
                
    def CalHash(self):
        hashdata = b"PLS1.0" + self.ClientNonce.__str__().encode() + self.ServerNonce.__str__().encode() + self.ClientPrekey + self.ServerPrekey
        block0 = hashlib.sha1(hashdata).hexdigest()
        block1 = hashlib.sha1(block0.encode()).hexdigest()
        block2 = hashlib.sha1(block1.encode()).hexdigest()
        block3 = hashlib.sha1(block2.encode()).hexdigest()
        block4 = hashlib.sha1(block3.encode()).hexdigest()
        keyset = block0.encode() + block1.encode() + block2.encode() + block3.encode() + block4.encode()
        self.EKc = keyset[0:32]
        self.EKs = keyset[32:64]
        self.IVc = keyset[64:96]
        self.IVs = keyset[96:128]
        self.MKc = keyset[128:160]
        self.MKs = keyset[160:192]
    
    def connection_lost(self,exc):
        print('Connection stopped because {}'.format(exc))
        