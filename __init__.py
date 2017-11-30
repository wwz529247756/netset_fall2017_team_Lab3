'''
Created on 2017年10月4日

@author: wangweizhou
'''
import playground
from playground.network.common import StackingProtocolFactory
from .TranCliProto import *
from .TranSerProto import *
from .PLSServer import *
from .PLSClient import *

lab3ClientFactory = StackingProtocolFactory(lambda: TranCliProto(),lambda:PLSClient())
lab3ServerFactory = StackingProtocolFactory(lambda: TranSerProto(),lambda:PLSServer())
lab3Connector = playground.Connector(protocolStack=(lab3ClientFactory, lab3ServerFactory))
playground.setConnector("lab3_protocol", lab3Connector)
