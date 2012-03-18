#!/usr/bin/python

from packetlib import Byte, StringSZ, Enum, ShortBE, BasePacketClass, AttrList,\
	Int, DynamicAttrClass
import random
from warnings import warn
import struct

class MacAddr(StringSZ):
	size=6
	def _init_new(self,data):
		if len(data)!=6: data=''.join([chr(int(x,16)) for x in data.split(':')])
		StringSZ._init_new(self,data)
	def _repr(self): return ':'.join(["%02x"%(ord(x)) for x in self.value])

IPProto=Enum.mk("IP ICMP IGMP", Byte, TCP=6, UDP=17, IPV6=41, IPV6Route=43, IPV6Frag=44, ESP=50, AH=51, IPV6ICMP=58)

class IPAddr(StringSZ):
	size=4
	def _init_new(self,data):
		if len(data)!=4: data=''.join([chr(int(x)) for x in data.split('.')])
		StringSZ._init_new(self,data)
	def _repr(self): return '.'.join(["%d"%(ord(x)) for x in self.value])

ArpOp=Enum.mk("? REQ REPL",ShortBE,"ArpOp")
EType=Enum.mk("",ShortBE,"EType",ARP=0x806,IP=0x800)

class ARP(BasePacketClass):
	_fields_=AttrList(
		('hwtype',ShortBE),("prottype",EType),
		("hwsize",Byte),("protsize",Byte), ("opcode",ArpOp),
		("hw_src",MacAddr),("prot_src",IPAddr),("hw_dst",MacAddr),("prot_dst",IPAddr))
	__slots__=_fields_.keys()+["oui"]
	@classmethod
	def new(cls,**attrs): return cls(**dict(dict(hwtype=1,prottype=EType("IP"),hwsize=6,protsize=4),**attrs))

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

def calc_cksum16(data):
	if len(data)%2: data="%s\0"%data
	cksum=sum(struct.unpack(">%sH"%(len(data)/2),data))
	while cksum>0xffff: cksum=(cksum&0xffff)+(cksum>>16)
	return (~cksum)&0xffff

class UDP(BasePacketClass):
	__slots__=['_parent_ip']
	_fields_=AttrList(('sport',ShortBE),('dport',ShortBE),('length',ShortBE),('cksum',ShortBE),('data',StringSZ))
	def get_data_size(self):
		return int(self.length-8)
	def get_length(self):
		return len(self.data)+8
	def get_cksum(self):
		try: ip=self._parent_ip
		except AttributeError:
			warn(Warning("UDP.cksum: no parent IP packet, will return 0 (bad for ipv6)"))
			return 0
		return calc_cksum16("".join(map(str,
				(ip.src,ip.dst,"\0",ip.proto,self.length,
				self.sport,self.dport,self.length,self.data))))

class IPv4(BasePacketClass):
	__slots__=[]
	_fields_=AttrList(('ver_len',Byte),('dsf',Byte,0),('length',ShortBE),
		('id',ShortBE),('frag_flags',ShortBE,0x4000),('ttl',Byte,64),('proto',IPProto),
		('hdr_cksum',ShortBE),('src',IPAddr),('dst',IPAddr),
		('options',StringSZ,''),('data',[({"proto":17},UDP),({},StringSZ)]))
	@property
	def hdr_size(self): return (self.ver_len&0xf)*4
	@property
	def data_size(self): return self.length-self.hdr_size
	@property
	def options_size(self): return self.hdr_size-20
	def get_hdr_cksum(self):
		return calc_cksum16("".join([str(getattr(self,x.name)) for x in
				self._fields_ if x.name not in ("data","hdr_cksum")
			]))
	def get_id(self):
		return random.randint(0,65535)
	def set_data(self, value):
		try: value._parent_ip=self
		except AttributeError,e: warn("failed setting IPv4.data._parent_ip: %r"%(e,))
		return value
	def get_proto(self):
		if isinstance(self.data,UDP): return IPProto("UDP")
		raise AttributeError("Cannot determine protocol of the packet")
	def get_length(self):
		return len(self.data)+self.hdr_size
	def get_ver_len(self):
		opts_len=len(self.options)
		if opts_len%4: raise ValueError("Size of IP options is not 32-bit aligned")
		return 0x40 | (5+opts_len/4)
	def _repr(self):
		return "%s %s bytes %s -> %s"%(int(self.length),self.proto._repr(),self.src._repr(),self.dst._repr())

class Ether(BasePacketClass):
	def choose_data(self,data,offset=None,size=None):
		if self.type&0x0800:
			if self.type==0x0800: return IPv4
			try: return StringSZ._c(size=self._data_size-self._offsetof("data"))
			except AttributeError: return StringSZ
		else: return LLC._c(size=int(self.type))
	_fields_=AttrList(("dst",MacAddr),("src",MacAddr),("type",EType),("data",[({"type":0x0806},ARP),({},choose_data)]),("trailer",StringSZ,""))
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

def arp_spoof(ethsock,ip,mac=None):
	if mac is None: mac=ethsock.sock.mac
	req=ethsock.r(data__opcode=ArpOp("REQ"),data__prot_dst=IPAddr(ip))
	repl=Ether(src=mac,dst=req.data.hw_src,type=EType("ARP"),data=ARP.new(opcode="REPL",hw_src=mac,hw_dst=req.data.hw_src,prot_src=ip,prot_dst=req.data.prot_src))
	ethsock.s(repl)
	return repl
