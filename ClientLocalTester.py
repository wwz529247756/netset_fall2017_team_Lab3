'''
Created on 2017年9月27日

@author: wangweizhou
'''
from playground.network.packet.fieldtypes import UINT32, STRING, BUFFER,BOOL
from playground.network.packet import PacketType
from playground.network.common import StackingProtocol
from playground.network.common import StackingProtocolFactory
from playground.network.common import StackingTransport
import playground
from PLSClient import *
from asyncio import *

if __name__=='__main__':
    loop = get_event_loop()
    connect = playground.getConnector().create_playground_connection (lambda:PLSClient(), '20174.1.1.1', 8000)
    transport, myclient = loop.run_until_complete(connect)
    #myclient.Login("wwz","hellowwz")
    loop.run_forever()
    loop.close()