'''
Created on 2017年9月28日

@author: wangweizhou
'''
from playground.network.packet.fieldtypes import UINT32, STRING, BUFFER,BOOL,LIST
from playground.network.packet import PacketType
from playground.network.common import StackingProtocol
from playground.network.common import StackingProtocolFactory
from playground.network.common import StackingTransport
import playground
from CertFactory import *
from asyncio import *
from PLSPackets import *
import hashlib
import random
from Crypto.Signature import PKCS1_v1_5
from Crypto.PublicKey import RSA




class PLSClient(Protocol):
    def __init__(self):
        self.privatekeyaddr = "/Users/wangweizhou/Desktop/public&private_key/Client/key.pem"
        self.certificateaddr = "/Users/wangweizhou/Desktop/public&private_key/Client/certificate.pem"
        self.transport = None
        self.ClientNonce = random.randint(10000,99999)
        self.ServerNonce = None
        self.deserializer = BasePacketType.Deserializer()
        self.privateKey = getPrivateKeyForAddr(self.privatekeyaddr)
        self.certificate = getCertificateForAddr(self.certificateaddr)
        self.ClientCert=LIST(BUFFER)
        self.ClientCert.append(self.certificate.encode())
        self.ServerCert=LIST(BUFFER)
        self.PacketsList = []
        
        
        
        
        
        
    def connection_made(self,transport):
        print("Client: PLS initialized!")
        self.transport=transport
        HelloPacket = PlsHello()
        HelloPacket.Nonce = self.ClientNonce
        HelloPacket.Certs = self.ClientCert  # required for modification
        self.transport.write(HelloPacket.__serialize__())
        self.PacketsList.append(HelloPacket)
        #print(self.certificate)
        
        
        
        
    def data_received(self,data):
        self.deserializer.update(data)
        for pkt in self.deserializer.nextPackets():
            if isinstance(pkt, PlsHello):
                print("PlsHello packet receive!")
                self.PacketsList.append(pkt)
                self.ServerNonce = pkt.Nonce
                self.ServerCert = pkt.Certs
                self.ServerCertificate = self.ServerCert[0].decode()
                #self.ClientPublickey = RSA.importKey(self.ClientCertificate)   #Client Public Key
                #print(self.ServerCertificate)
                KeyExchangePacket = PlsKeyExchange()
                self.ClientPrekey = b"Need to be encrypted!"
                '''
                    Encrypt self.ClientPrekey here!
                '''
                KeyExchangePacket.PreKey = self.ClientPrekey
                KeyExchangePacket.NoncePlusOne = self.ServerNonce+1;
                self.transport.write(KeyExchangePacket.__serialize__())
                print("KeyExchange sent!")
                self.PacketsList.append(KeyExchangePacket)
                #print(self.ServerNonce.__str__().encode())
            if isinstance(pkt, PlsKeyExchange):
                print("PlskeyExchange receive!")
                self.PacketsList.append(pkt)
                '''
                    Decrypt pkt.PreKey here!
                '''
                self.ServerPrekey = pkt.PreKey
                self.validation = b''
                for packet in self.PacketsList:
                    pktdata = packet.__serialize__()
                    self.validation = self.validation+pktdata
                self.hashvalidation = hashlib.sha1(self.validation).hexdigest()
                HandshakeDonePacket = PlsHandshakeDone()
                HandshakeDonePacket.ValidationHash = self.hashvalidation.encode()
                self.transport.write(HandshakeDonePacket.__serialize__())
                print("HandshakeDone packet sent!")
            if isinstance(pkt, PlsHandshakeDone):
                print("Handshake Done!")
                self.CalHash()
                
                
            
                
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
    
        