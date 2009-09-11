#!/usr/bin/python

from packetlib import *
from ethernet import *

apple_bcast="09:00:07:ff:ff:ff".replace(":","").decode("hex")

def ddp_cksum(data):
	cksum=0
	for b in map(lambda x: ord(x),str(data)):
		cksum=(cksum+b)<<1
		if(cksum & 0x10000): cksum=(cksum+1)&0xffff
	if cksum==0: cksum=0xffff
	return cksum


class ByteSZString(BasePacketClass):
	_fields_=AttrList(("str_size",Byte),("str",StringSZ))
	__slots__=_fields_.keys()
	def _repr(self): return self.str._repr()
	def _init_new(self,data): self.str=data

class NBPNode(BasePacketClass):
	_fields_=AttrList(("net",ShortBE),("node",Byte),("port",Byte),("enum",Byte),("object",ByteSZString),("type",ByteSZString),("zone",ByteSZString))
	__slots__=_fields_.keys()
	def _repr(self): return "%d.%d:%d"%(self.net,self.node,self.port)

class NBP(BasePacketClass):
	_fields_=AttrList(("info",Byte),("tid",Byte),("nodes",ArrayAttr._c(dtype=NBPNode)))
	__slots__=_fields_.keys()+["nodes_count"]
	def get_nodes_count(self): return int(self.info)&0xf
	def set_nodes_count(self,count): self.info=(int(self.info)&0xf0) | count
	@classmethod
	def new_lookup(cls,net,node,port=128,**attrs):
		return cls(**dict(dict(info=0x21,tid=1,nodes=[NBPNode(net=net,node=node,port=port,enum=0,object="=",type="=",zone="*")]),**attrs))

class DDP(BasePacketClass):
	_fields_=AttrList(("size",ShortBE),("cksum",ShortBE),("dnet",ShortBE),("snet",ShortBE),("dnode",Byte),("snode",Byte),("dsock",Byte),("ssock",Byte),("type",Byte),("data",[({'type':2},NBP),({},StringSZ)]))
	__slots__=_fields_.keys()
	def get_size(self): return self._offsetof("data")+len(self.data)
	def get_cksum(self):
		return ddp_cksum("".join([str(x) for x in (self.dnet,self.snet,self.dnode,self.snode,self.dsock,self.ssock,self.type,self.data)]))
	@classmethod
	def new_bcast(cls,**attrs):
		return cls(**dict(dict(dnet=0,dnode=0xff),**attrs))

LLC.register_atype("data",(dict(oui=0x80007,type=0x809b),DDP))

def make_query(snet,snode,mac=None):
	if mac is None: mac=n.sock.mac
	if type(mac) in (str,unicode) and len(mac)!=6: mac=mac.replace(':','')
	return Ether(src=mac.decode("hex"),dst=apple_bcast,data=LLC.new_atalk(data=DDP.new_bcast(type=2,dsock=2,ssock=2,snet=snet,snode=snode,data=NBP.new_lookup(snet,snode))))

if __name__=='__main__':
	import user,netutil
	mynode=(65280,99)
	n=PktHandler(sock=netutil.Interface("eth0"))
	print "use n.sr, n.s and n.r,  n is a %r"%(n)
