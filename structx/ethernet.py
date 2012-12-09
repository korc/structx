#!/usr/bin/python

from structx.packetlib import Byte, StringSZ, Enum, ShortBE, BasePacketClass, AttrList,\
	Int, DynamicAttrClass, ArrayAttr, Short, IntBE, Flags, Quad
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

class TCP(BasePacketClass):
	__slots__=['_parent_ip']
	_fields_=AttrList(('sport', ShortBE),('dport', ShortBE),('seq', IntBE),('ack', IntBE),
		('flags', Flags.mk('fin syn reset push ack urg ecn cwr ns', ShortBE)),
		('window_size', ShortBE), ('cksum', ShortBE), ('urg_ptr', ShortBE, 0),
		('options', StringSZ), ('data',[({},StringSZ)]))
	@property
	def hdr_len(self): return self.flags[12:]*4
	def get_options_size(self):
		return self.hdr_len-20
	@hdr_len.setter
	def hdr_len(self, v):
		assert v%4==0
		self.flags[12:]=v/4
	def get_cksum(self):
		try: ip=self._parent_ip
		except AttributeError:
			warn("TCP.cksum: no parent IP packet, will return 0")
			return 0
		return calc_cksum16("".join(map(str,
			(ip.src, ip.dst, '\0', ip.proto,
			ShortBE(int(self.hdr_len)+len(self.data)),
			self.sport, self.dport, self.seq, self.ack, self.flags, self.window_size,
			self.urg_ptr, self.options, self.data
			))))

class IPv4(BasePacketClass):
	__slots__=[]
	_fields_=AttrList(('ver_len',Byte),('dsf',Byte,0),('length',ShortBE),
		('id',ShortBE),('frag_flags',ShortBE,0x4000),('ttl',Byte,64),('proto',IPProto),
		('hdr_cksum',ShortBE),('src',IPAddr),('dst',IPAddr),
		('options',StringSZ,''),('data',[({"proto":17},UDP), ({"proto":6}, TCP), ({},StringSZ)]))
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

class PCapPacket(BasePacketClass):
	__slots__=[]
	dtype=StringSZ
	def choose_dtype(self, data, offset=None, size=None):
		return self.dtype
	_fields_=AttrList(('ts_sec', Int), ('ts_usec', Int), ('data_size', Int), ('data_size_orig', Int), ('data', choose_dtype))
	def _repr(self): return "%s %s bytes at %ss+%sms"%(int(self.data_size), type(self.data).__name__, int(self.ts_sec),int(self.ts_usec))

PCapNetwork=Enum.mk("null ethernet", Int, ieee802_5=6, arcnet_bsd=7, slip=8, ppp=9, fddi=10, ppp_hdlc=50, ppp_ether=51, raw_ip=101, ieee802_11=105, loop=108, linux_sll=113, ieee802_15_4=195, ipv4=228, ipv6=229)

class PCapFile(BasePacketClass):
	__slots__=[]
	def choose_pcap_packet(self,data,offset=None,size=None):
		if self.network.name=='ethernet':
			return ArrayAttr._c(dtype=PCapPacket._c(dtype=Ether))
		else: return ArrayAttr._c(dtype=PCapPacket)
	_fields_=AttrList(
		('magic', Int, 0xa1b2c3d4), ('major', Short, 2), ('minor', Short, 4), ('thiszone', Int, 0), ('sigfigs', Int, 0), ('snaplen', Int), ('network', PCapNetwork, 1),
		('data', choose_pcap_packet))

class PCapNGBlockOption(BasePacketClass):
	__slots__=[]
	_fields_=AttrList(("code", Enum.mk("end comment", Short)), ("data_size", Short), ("data", StringSZ), ("datapad", StringSZ))
	def get_datapad_size(self): return (4-int(self.data_size)%4)%4

class PCapNGBlock(BasePacketClass):
	__slots__=[]
	class EBPData(BasePacketClass):
		__slots__=[]
		_fields_=AttrList(('if_id', Int), ("ts_high", Int), ("ts_low", Int), ("data_size", Int), ("pkt_len", Int), ("data", StringSZ), ("datapad", StringSZ), ("options", StringSZ))
		def get_datapad_size(self):
			mod=int(self.data_size)%4
			return 4-mod if mod else 0
	class SHBData(BasePacketClass):
		__slots__=[]
		_fields_=AttrList(('bom', Int), ('v_maj', Short), ('v_min', Short), ('sect_len', Quad), ('options', ArrayAttr._c(dtype=PCapNGBlockOption, end="\0\0\0\0")))
	class IDBData(BasePacketClass):
		__slots__=[]
		_fields_=AttrList(('linktype', PCapNetwork), ('rsvd', Short, 0), ('snaplen', Int), ('options', ArrayAttr._c(dtype=PCapNGBlockOption, end="\0\0\0\0")))
	_fields_=AttrList(
		("type", Enum.mk("? IDB PB SPB NRB ISB EBP", Int, SHB=0x0A0D0D0A)),
		("block_len", Int), ("data", [
				({"type":0x0a0d0d0a}, SHBData), ({"type":1}, IDBData), ({"type":6},EBPData), ({},StringSZ)
			]), ("block_len2", Int))
	def get_data_size(self):
		return self.block_len-12
	def _repr(self): return self.type.name

class PCapNGFile(BasePacketClass):
	__slots__=[]
	_fields_=AttrList(("blocks",ArrayAttr._c(dtype=PCapNGBlock)))

def arp_spoof(ethsock,ip,mac=None):
	if mac is None: mac=ethsock.sock.mac
	req=ethsock.r(data__opcode=ArpOp("REQ"),data__prot_dst=IPAddr(ip))
	repl=Ether(src=mac,dst=req.data.hw_src,type=EType("ARP"),data=ARP.new(opcode="REPL",hw_src=mac,hw_dst=req.data.hw_src,prot_src=ip,prot_dst=req.data.prot_src))
	ethsock.s(repl)
	return repl
