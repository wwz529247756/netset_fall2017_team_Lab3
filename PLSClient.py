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
from myTransport2 import *
from Crypto.Util import Counter
from Crypto.Cipher import AES
import codecs 
from Crypto.Hash import HMAC, SHA
import OpenSSL




class PLSClient(StackingProtocol):
    def __init__(self):
        super().__init__
        self.privatekeyaddr = "/Users/wangweizhou/Desktop/public&private_key/Client/key.pem"
        self.certificateaddr = "/Users/wangweizhou/Desktop/public&private_key/Client/certificate.pem"
        self.transport = None
        self.ClientNonce = random.randint(10000,99999)
        self.ServerNonce = None
        self.deserializer = BasePacketType.Deserializer()
        self.privateKeystring = getPrivateKeyForAddr(self.privatekeyaddr)
        self.privateKey = RSA.importKey(self.privateKeystring)
        self.certificate = getCertificateForAddr(self.certificateaddr)
        self.ClientCert=LIST(BUFFER)
        self.ClientCert.append(self.certificate.encode())
        self.ServerCert=LIST(BUFFER)
        self.PacketsList = []
        
        
        
        
        
        
    def connection_made(self,transport):
        print("Client: PLS initialized!")
        self.transport=transport
        self.higherTransport = PlsTransport(self.transport, self)
        #self.higherProtocol().connection_made(higherTransport)
        HelloPacket = PlsHello()
        HelloPacket.Nonce = self.ClientNonce
        HelloPacket.Certs = self.ClientCert  # required for modification
        self.transport.write(HelloPacket.__serialize__())
        self.PacketsList.append(HelloPacket)
        self.status =0
        #print(self.certificate)
        
        
        
        
    def data_received(self,data):
        self.deserializer.update(data)
        for pkt in self.deserializer.nextPackets():
            if self.status ==0:
                if isinstance(pkt, PlsHello):
                    print("Client: PlsHello packet receive!")
                    self.PacketsList.append(pkt)
                    self.ServerNonce = pkt.Nonce
                    self.ServerCert = pkt.Certs
                    self.ServerCertificate = self.ServerCert[0].decode()
                    self.tmpPublickey = OpenSSL.crypto.load_certificate(OpenSSL.crypto.FILETYPE_PEM, self.ServerCertificate).get_pubkey()
                    self.publickeystring = OpenSSL.crypto.dump_publickey(OpenSSL.crypto.FILETYPE_PEM, self.tmpPublickey).decode()
                    self.serverPublicKey = RSA.importKey(self.publickeystring)
                    KeyExchangePacket = PlsKeyExchange()
                    self.ClientPrekey = b"helloworld"
                    cipher = self.serverPublicKey.encrypt(self.ClientPrekey, 32)[0]
                    KeyExchangePacket.PreKey = cipher
                    KeyExchangePacket.NoncePlusOne = self.ServerNonce+1;
                    self.transport.write(KeyExchangePacket.__serialize__())
                    print("Client: KeyExchange sent!")
                    self.PacketsList.append(KeyExchangePacket)
                    #print(self.ServerNonce.__str__().encode())
                if isinstance(pkt, PlsKeyExchange):
                    print("Client: PlskeyExchange receive!")
                    self.PacketsList.append(pkt)
                    self.ServerPrekey = self.privateKey.decrypt(pkt.PreKey)
                    self.validation = b''
                    for packet in self.PacketsList:
                        pktdata = packet.__serialize__()
                        self.validation = self.validation+pktdata
                    self.hashvalidation = hashlib.sha1(self.validation).hexdigest()
                    HandshakeDonePacket = PlsHandshakeDone()
                    HandshakeDonePacket.ValidationHash = self.hashvalidation.encode()
                    self.transport.write(HandshakeDonePacket.__serialize__())
                    print("Client: HandshakeDone packet sent!")
                if isinstance(pkt, PlsHandshakeDone):
                    print("Client: Handshake Done!")
                    self.CalHash()
                    self.higherProtocol().connection_made(self.higherTransport)
                    self.status =1
            if self.status ==1:
                if isinstance(pkt, PlsData):
                    if pkt.Mac == self.VerificationEngine(pkt.Ciphertext):
                        higherData = self.decryptEngine(pkt.Ciphertext)
                        self.higherProtocol().data_received(higherData)
            
    def VerificationEngine(self, ciphertext):
        hm = HMAC.new(self.MKs, digestmod=SHA)
        hm.update(ciphertext)
        return hm.digest()
    
    def MacEngine(self, ciphertext):
        hm = HMAC.new(self.MKc, digestmod=SHA)
        hm.update(ciphertext)
        return hm.digest()
                
    def encryptEngine(self, plaintext):
        crt = Counter.new(128, initial_value=int(codecs.encode(self.IVc, 'hex_codec'),16))
        aesEncrypter = AES.new(self.EKc, counter=crt, mode=AES.MODE_CTR)
        ciphertext = aesEncrypter.encrypt(plaintext)
        return ciphertext
    
    def decryptEngine(self, ciphertext):
        crt = Counter.new(128, initial_value=int(codecs.encode(self.IVs, 'hex_codec'),16))
        aesDecrypter = AES.new(self.EKs, counter=crt, mode=AES.MODE_CTR)
        plaintext = aesDecrypter.decrypt(ciphertext)
        return plaintext
    
    
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
    
        