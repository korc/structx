#!/usr/bin/python

from packetlib import *

DnsQueryType=Enum.mk('? A NS',ShortBE,PTR=0xc,SRV=0x21,TXT=0x10)

class DnsPtrString(StringSZ):
	__slots__=['data','data_offset']
	def _init_new(self,data):
		self.value='%s\x00'%''.join(['%c%s'%(len(x),x) for x in data.split('.')])
		self.size=len(self.value)
	def _init_parse(self,data,data_offset,data_size):
		end=data_offset
		while True:
			code=ord(data[end])
			end+=1
			if code==0: break
			elif code&0xc0:
				end+=1
				break
			elif code<=0x20: end+=code
		self.data,self.data_offset=data,data_offset
		self.value=data[data_offset:end]
		self.size=end-data_offset
	def decode_name(self,data,offset):
		ret=[]
		if data is None: data=self.value
		while True:
			code=ord(data[offset])
			offset+=1
			if code==0: break
			elif code&0xc0:
				ret.append(self.decode_name(self.data,((code&~0xc0)<<8)+ord(data[offset])))
				break
			elif code<=0x20:
				ret.append(data[offset:offset+code])
				offset+=code
		return '.'.join(ret)
	def _repr(self,data=None,offset=0):
	 	return repr(self.decode_name(self.value,0))

class DnsRecTXT(BasePacketClass):
	_fields_=AttrList(('txt_size',Byte),('txt',StringSZ))
	__slots__=_fields_.keys()
	def _repr(self): return self.txt._repr()

class DnsRecIP(IntBE):
	__slots__=[]
	def _repr(self): return socket.inet_ntoa(str(self))

class DnsRecSRV(BasePacketClass):
	_fields_=AttrList(('priority',ShortBE),('weight',ShortBE),('port',ShortBE),('target',DnsPtrString))
	__slots__=_fields_.keys()


class DnsPacketRecord(BasePacketClass):
	def choose_data_type(self,data,offset=0,size=None):
		if self.type.name=='A': return DnsRecIP
		elif self.type.name=='TXT': return ArrayAttr._c(dtype=DnsRecTXT)
		elif self.type.name=='SRV': return DnsRecSRV
		elif self.type.name=='NS': return DnsPtrString
		else: return StringSZ
	_fields_=AttrList(('name',DnsPtrString),('type',DnsQueryType),('cls',ShortBE,1),('ttl',IntBE,0xff),('data_size',ShortBE),('data',choose_data_type))
	__slots__=_fields_.keys()
	def _repr(self): return '%s %s'%(self.name._repr(),self.type._repr())

class DnsPacketQRecord(DnsPacketRecord):
	_fields_=DnsPacketRecord._fields_.dup(ttl=[],data_size=[],data=[])
	__slots__=_fields_.keys()

class DnsPacket(BasePacketClass):
	_fields_=AttrList(
		('tid',ShortBE,0),('flags',ShortBE,0),
		('q_count',ShortBE),('answ_count',ShortBE),('auth_count',ShortBE),('add_count',ShortBE),
		('q',ArrayAttr._c(dtype=DnsPacketQRecord),[]),
		('answ',ArrayAttr._c(dtype=DnsPacketRecord),[]),
		('auth',ArrayAttr._c(dtype=DnsPacketRecord),[]),
		('add',ArrayAttr._c(dtype=DnsPacketRecord),[]),
	)
	__slots__=_fields_.keys()
