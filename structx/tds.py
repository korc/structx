#!/usr/bin/python

from packetlib import *

TDSPktType=Enum.mk("? Query Login ? Response",Byte,"TDSPktType",TDS78=0x12)
TDSPktStatus=Enum.mk("Last NotLast",Byte,"TDSPktStatus")
TDSTknType=Enum.mk("",Byte,"TDSTknType",EnvChange=0xe3,InfoMsg=0xab,LoginAck=0xad,Done=0xfd)

class TDSToken(BasePacketClass):
	_fields_=AttrList(('tokentype',TDSTknType),('tokenlen',Short),('data',StringSZ))
	__slots__=_fields_.keys()+["size","data_size"]
	def get_size(self): return int(self.tokenlen)+3
	def get_data_size(self): return int(self.tokenlen)+3

class TDSPacket(BasePacketClass):
	_fields_=AttrList(('pkttype',TDSPktType),('status',TDSPktStatus),('size',ShortBE),('channel',ShortBE),('pktnr',Byte),('window',Byte),('data',ArrayAttr._c(dtype=TDSToken)))
	__slots__=_fields_.keys()
