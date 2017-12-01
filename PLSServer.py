'''
Created on 2017年9月28日

@author: wangweizhou
'''
from playground.network.packet.fieldtypes import UINT32, STRING, BUFFER,BOOL,LIST
from playground.network.packet import PacketType
from playground.network.common import StackingProtocol
from playground.network.common import StackingProtocolFactory
from playground.network.common import StackingTransport
from .CertFactory import *
import playground
from asyncio import *
import random
from .PLSPackets import *
from Crypto.Signature import PKCS1_v1_5
from Crypto.PublicKey import RSA
import hashlib
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

#import playground.crypto


class PLSServer(StackingProtocol):
    def __init__(self):
        self.transport = None
        self.ClientNonce = None
        self.ServerNonce = random.randint(10000,99999)
        self.deserializer = BasePacketType.Deserializer()
        self.ServerCert=LIST(BUFFER)
        self.ClientCert=LIST(BUFFER)
        self.PacketList = []
        self.status = 0
        self.Certobject = []
        
    def connection_made(self,transport):
        address, port = transport.get_extra_info("sockname")
        self.rawKey = getPrivateKeyForAddr(address)
        self.privateKey = RSA.importKey(self.rawKey)
        self.ServerCert = getCertificateForAddr(address)
        self.transport=transport
        self.higherTransport = PlsTransport(self.transport, self)
        
        
    def data_received(self,data):
        self.data = data
        self.deserializer.update(data)
        for pkt in self.deserializer.nextPackets():
            if self.status == 0:
                self.PacketList.append(pkt)
                if isinstance(pkt, PlsHello):
                    self.ClientCert = pkt.Certs
                    if self.ChainVerifyer(self.ClientCert):
                        print("Server: Hellopacket receive!")
                        self.ClientNonce = pkt.Nonce
                        self.ClientCertificate = self.ClientCert[0].decode()
                        self.tmpPublickey = OpenSSL.crypto.load_certificate(OpenSSL.crypto.FILETYPE_PEM, self.ClientCertificate).get_pubkey()
                        self.publickeystring = OpenSSL.crypto.dump_publickey(OpenSSL.crypto.FILETYPE_PEM, self.tmpPublickey).decode()
                        self.clientPublicKey = RSA.importKey(self.publickeystring)
                        HelloPacket = PlsHello()
                        HelloPacket.Nonce = self.ServerNonce
                        HelloPacket.Certs = self.ServerCert
                        self.transport.write(HelloPacket.__serialize__())
                        self.PacketList.append(HelloPacket)
                    else:
                        print("Server: Authentication ERROR!")
                     
                    
                        
                    #print(self.ClientCertificate)
                    
                if isinstance(pkt, PlsKeyExchange):
                    print("Server: PlsKeyExchange receive!")
                    self.PacketList.append(pkt)
                    self.ClientPrekey = PKCS1OAEP_Cipher(self.privateKey, None, None, None).decrypt(pkt.PreKey)
                    KeyExchangePacket = PlsKeyExchange()
                    self.ServerPrekey = os.urandom(16)
                    Encrypter = PKCS1OAEP_Cipher(self.clientPublicKey, None, None, None)
                    cipher = Encrypter.encrypt(self.ServerPrekey)
                    KeyExchangePacket.PreKey = cipher
                    KeyExchangePacket.NoncePlusOne = self.ClientNonce+1
                    self.transport.write(KeyExchangePacket.__serialize__())
                    print("Server: KeyExchange sent!")
                    self.PacketList.append(KeyExchangePacket)
                    
                if isinstance(pkt, PlsHandshakeDone):
                    print("Server: PlsHandshakeDone receive!")
                    self.validation =b''
                    for packet in self.PacketList:
                        pktdata = packet.__serialize__()
                        self.validation = self.validation+pktdata
                    self.hashvalidation = hashlib.sha1(self.validation).hexdigest()
                    HandshakeDonePacket = PlsHandshakeDone()
                    HandshakeDonePacket.ValidationHash = self.hashvalidation.encode()
                    self.transport.write(HandshakeDonePacket.__serialize__())
                    self.CalHash()
                    self.encrt = Counter.new(128, initial_value=int(hexlify(self.IVs),16))
                    self.aesEncrypter = AES.new(self.EKs, counter=self.encrt, mode=AES.MODE_CTR)
                    self.decrt = Counter.new(128, initial_value=int(hexlify(self.IVc),16))
                    self.aesDecrypter = AES.new(self.EKc, counter=self.decrt, mode=AES.MODE_CTR)
                    
                    self.higherProtocol().connection_made(self.higherTransport)
                    self.status=1
                
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
        hm = HMAC.new(self.MKc, digestmod=SHA)
        hm.update(ciphertext)
        return hm.digest()
    
    def MacEngine(self, ciphertext):
        hm = HMAC.new(self.MKs, digestmod=SHA)
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
        