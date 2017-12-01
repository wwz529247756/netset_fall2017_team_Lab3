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
from .CertFactory import *
from asyncio import *
from .PLSPackets import *
import hashlib
import random
from Crypto.Signature import PKCS1_v1_5
from Crypto.PublicKey import RSA
from .myTransport2 import *
from Crypto.Util import Counter
from Crypto.Cipher import AES
import codecs 
from Crypto.Hash import HMAC, SHA
import OpenSSL
from playground.common.CipherUtil import RSA_SIGNATURE_MAC
from cryptography import x509
from cryptography.hazmat.backends import default_backend
from cryptography.x509.oid import NameOID
import os
from Crypto.Cipher.PKCS1_OAEP import PKCS1OAEP_Cipher
from binascii import hexlify



class PLSClient(StackingProtocol):
    def __init__(self):
        super().__init__
        
        self.ClientNonce = random.randint(10000,99999)
        self.ServerNonce = None
        self.deserializer = BasePacketType.Deserializer()
        self.ClientCert=LIST(BUFFER)
        self.ServerCert=LIST(BUFFER)
        self.PacketsList = []
        self.Certobject = []
        
        
        
        
        
        
    def connection_made(self,transport):
        address, port = transport.get_extra_info("sockname")
        self.rawKey = getPrivateKeyForAddr(address)
        self.privateKey = RSA.importKey(self.rawKey)
        self.ClientCert = getCertificateForAddr(address)
        
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
                    self.ServerCert = pkt.Certs
                    if self.ChainVerifyer(self.ServerCert):
                        print("Client: PlsHello packet receive!")
                        self.PacketsList.append(pkt)
                        self.ServerNonce = pkt.Nonce
                        self.ServerCertificate = self.ServerCert[0].decode()
                        self.tmpPublickey = OpenSSL.crypto.load_certificate(OpenSSL.crypto.FILETYPE_PEM, self.ServerCertificate).get_pubkey()
                        self.publickeystring = OpenSSL.crypto.dump_publickey(OpenSSL.crypto.FILETYPE_PEM, self.tmpPublickey).decode()
                        self.serverPublicKey = RSA.importKey(self.publickeystring)
                        KeyExchangePacket = PlsKeyExchange()
                        self.ClientPrekey = os.urandom(16)
                        Encrypter = PKCS1OAEP_Cipher(self.serverPublicKey, None, None, None)
                        cipher = Encrypter.encrypt(self.ClientPrekey)
                        KeyExchangePacket.PreKey = cipher
                        KeyExchangePacket.NoncePlusOne = self.ServerNonce+1
                        self.transport.write(KeyExchangePacket.__serialize__())
                        print("Client: KeyExchange sent!")
                        self.PacketsList.append(KeyExchangePacket)
                    else:
                        print("Client: Authentication Error!")
                    
                        
                        
                if isinstance(pkt, PlsKeyExchange):
                    print("Client: PlskeyExchange receive!")
                    self.PacketsList.append(pkt)
                    self.ServerPrekey = PKCS1OAEP_Cipher(self.privateKey, None, None, None).decrypt(pkt.PreKey)
                    self.validation = b''
                    for packet in self.PacketsList:
                        pktdata = packet.__serialize__()
                        self.validation = self.validation+pktdata
                    self.hashvalidation = hashlib.sha1(self.validation).digest()
                    HandshakeDonePacket = PlsHandshakeDone()
                    HandshakeDonePacket.ValidationHash = self.hashvalidation
                    self.transport.write(HandshakeDonePacket.__serialize__())
                    print("Client: HandshakeDone packet sent!")
                if isinstance(pkt, PlsHandshakeDone):
                    print("Client: Handshake Done!")
                    self.CalHash()
                    self.encrt = Counter.new(128, initial_value=int(hexlify(self.IVc),16))
                    self.aesEncrypter = AES.new(self.EKc, counter=self.encrt, mode=AES.MODE_CTR)
                    self.decrt = Counter.new(128, initial_value=int(hexlify(self.IVs),16))
                    self.aesDecrypter = AES.new(self.EKs, counter=self.decrt, mode=AES.MODE_CTR)
                    self.higherProtocol().connection_made(self.higherTransport)
                    self.status =1
                    
                if isinstance(pkt, PlsClose):
                    self.connection_lost("Error raised!")
                
            if self.status ==1:
                if isinstance(pkt, PlsData):
                    if pkt.Mac == self.VerificationEngine(pkt.Ciphertext):
                        higherData = self.decryptEngine(pkt.Ciphertext)
                        self.higherProtocol().data_received(higherData)
    
    
    
    def ChainVerifyer(self, certs):
        for cert in certs:
            self.Certobject.append(x509.load_pem_x509_certificate(cert, default_backend()))
        
        address = self.transport.get_extra_info("peername")[0]
        if(address!=self.Certobject[0].subject.get_attributes_for_oid(NameOID.COMMON_NAME)[0].value):
            return False
        
        verifyaddr = address
        for i in range(len(self.Certobject)):
            if(verifyaddr.startswith(self.Certobject[i].subject.get_attributes_for_oid(NameOID.COMMON_NAME)[0].value)):
                verifyaddr = self.Certobject[i].subject.get_attributes_for_oid(NameOID.COMMON_NAME)[0].value
            else:
                return False
        
        
        for i in range(len(self.Certobject)-1):
            this = self.Certobject[i]
            issuer = RSA_SIGNATURE_MAC(self.Certobject[i+1].public_key())
            if not issuer.verify(this.tbs_certificate_bytes, this.signature):
                return False
        print("Certification Authentication Passed!")
        return True
    
    
    
    
    
    def VerificationEngine(self, ciphertext):
        hm = HMAC.new(self.MKs, digestmod=SHA)
        hm.update(ciphertext)
        return hm.digest()
    
    def MacEngine(self, ciphertext):
        hm = HMAC.new(self.MKc, digestmod=SHA)
        hm.update(ciphertext)
        return hm.digest()
                
    def encryptEngine(self, plaintext):
        ciphertext = self.aesEncrypter.encrypt(plaintext)
        return ciphertext
    
    def decryptEngine(self, ciphertext):
        plaintext = self.aesDecrypter.decrypt(ciphertext)
        return plaintext
    
    
    def CalHash(self):
        hashdata = b'PLS1.0' + self.ClientNonce.to_bytes(8,byteorder="big") + self.ServerNonce.to_bytes(8,byteorder="big") + self.ClientPrekey + self.ServerPrekey
        block0 = hashlib.sha1(hashdata).digest()
        block1 = hashlib.sha1(block0).digest()
        block2 = hashlib.sha1(block1).digest()
        block3 = hashlib.sha1(block2).digest()
        block4 = hashlib.sha1(block3).digest()
        keyset = block0 + block1 + block2 + block3 + block4
        
        self.EKc = keyset[0:16]
        self.EKs = keyset[16:32]
        self.IVc = keyset[32:48]
        self.IVs = keyset[48:64]
        self.MKc = keyset[64:80]
        self.MKs = keyset[80:96]
       
    
    def connection_lost(self,exc):
        print('Connection stopped because {}'.format(exc))
    
        