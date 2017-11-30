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
                        self.ClientPrekey = b"helloworld"
                        cipher = self.serverPublicKey.encrypt(self.ClientPrekey, 32)[0]
                        KeyExchangePacket.PreKey = cipher
                        KeyExchangePacket.NoncePlusOne = self.ServerNonce+1;
                        self.transport.write(KeyExchangePacket.__serialize__())
                        print("Client: KeyExchange sent!")
                        self.PacketsList.append(KeyExchangePacket)
                    else:
                        print("Client: Authentication Error!")
                    
                        
                        
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
    
        
