'''
Created on 2017年11月8日

@author: wangweizhou
'''
from playground.network.common import StackingTransport
from PLSPackets import *

class PlsTransport(StackingTransport):
    def __init__(self, lowerTransport, protocol):
        super().__init__(lowerTransport, extra=None)
        self._lowerTransport = lowerTransport
        self.protocol = protocol
        
    def write(self, data):   # higher layer protocol will call this function from transmission
        self.data = data
        
        self.encryptData = self.protocol.encryptEngine(self.data)  # should be modified after encryption
        dataPacket = PlsData()
        dataPacket.Ciphertext = self.encryptData
        dataPacket.Mac = self.protocol.MacEngine(self.encryptData)
        self.lowerTransport().write(dataPacket.__serialize__())
    
    