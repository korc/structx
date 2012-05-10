#!/usr/bin/python

from packetlib import *
from protlib import *

import os
import time,random

import Crypto.Hash.MD4,Crypto.Hash.HMAC

version=(0,1,20090904)

CapaFlags=Flags.mk('raw mpx unicode lg  ntsmb rpc ntst l2lock  lock ntfind ? ?  dfs infopthru lg_rdx lg_wrx  ? ? ? ?  ? ? ? unix  ? ? ? ?  ? bulk cmpr extsec')

AMaskFlags=Flags.mk('rd wr append rdea  wrea exe delchld rdatt  wratt ? ? ?  ? ? ? ?  del rdctl wrdac wrown  sync ? ? ?  syssec mxallow ? ?  genall genexe genwr genrd')

FileAttrFlags=Flags.mk('ro hid sys volid  dir arch dev norm  tmp sparse reparsepnt cmpr  offline indexed enc',Int)
ShAccFlags=Flags.mk('rd wr del',Int)
CrOptsFlags=Flags.mk('dir wrthru seqonly imbuf  syncalrt syncnoalrt nondir ctcon  complopl noea eight3 rndacc  delclose fidopen backup nocmpr  ? ? ? ?  rsrvopfilter reparsepnt norecall spcquery',Int)

def mknthash(passwd):
	return Crypto.Hash.MD4.new(passwd.encode('utf-16-le')).digest()

class NTLMv2Resp(BasePacketClass):
	class NBName(BasePacketClass):
		_fields_=AttrList(('ntype',Short),('name_size',Short),('name',WStringSZ))
		__slots__=_fields_.keys()
	class SecBlob(BasePacketClass):
		_fields_=AttrList('\x01\x01\x00\x00\x00\x00\x00\x00',('time',Quad),('clchl',StringSZ._c(size=8)),('ukn',Int,0),('nlist',StringSZ))
		__slots__=_fields_.keys()
		def get_time(self): return int((time.time()+11644473600)*10000000)
		def get_clchl(self): return struct.pack('Q',random.randint(0,(1<<64)-1))
		def get_nlist(self): return '\x00\x00\x00\x00'

	def get_v1hash(self):
		return Crypto.Hash.MD4.new(self.passwd.encode('utf-16-le')).digest()
	def get_v2hash(self):
		return Crypto.Hash.HMAC.new(self.v1hash,'%s%s'%(self.user.upper().encode('utf-16-le'),self.dest.upper().encode('utf-16-le'))).digest()
	def get_hmac(self):
		return Crypto.Hash.HMAC.new(self.v2hash,'%s%s'%(self.srvchl,self.blob)).digest()
	def get_lmv2resp(self):
		return '%s%s'%(Crypto.Hash.HMAC.new(self.v2hash,'%s%s'%(self.srvchl,self.blip)).digest(),self.blip)
	def get_blob(self):
		return self.SecBlob()
	def get_blip(self): return struct.pack('Q',random.randint(0,(1<<64)-1))

	def choose_secblob(self,data,data_offset=0,data_size=None):
		hdr=self.SecBlob._fields_.flow[0]
		if data[data_offset:data_offset+len(hdr)].startswith(hdr):
			return self.SecBlob
		else: return StringSZ

	_fields_=AttrList(('hmac',StringSZ._c(size=16)),('blob',choose_secblob))
	__slots__=_fields_.keys()+['passwd','v1hash','v2hash','user','dest','srvchl','lmv2resp','blip']

class BrokenWStringZ(WStringZ):
	__slots__=['is_broken']
	def __str__(self):
		if self.is_broken: return '%s\x00'%self.value.encode('utf-16-le')
		else: return WStringZ.__str__(self)
	def _init_parse(self,data,data_offset,data_size):
		try: WStringZ._init_parse(self,data,data_offset,data_size)
		except ValueError:
			self.is_broken=True
			idx=data.index('\x00\x00',data_offset)
			self.value=data[data_offset:idx+1].decode('utf-16-le')
			self.size=len(self.value)*2+1
		else: self.is_broken=False

class SmbCmd(Enum):
	__slots__=[]
	fmt=Byte.fmt
	enum,enum_rev=Enum.mkenum2(negprot=0x72,setupnx=0x73,tconx=0x75,ntcreatenx=0xa2,trans=0x25)
	class NegRespWD(BasePacketClass):
		_fields_=AttrList(('idx',Short),('secmode',Byte),('maxmpx',Short),('maxvc',Short),('maxbuf',Int),('maxraw',Int),('sesskey',Int),('capabilities',CapaFlags),('systime',Quad),('tz',Short),('keysize',Byte))
		__slots__=_fields_.keys()
	class NegRespBDESN(BasePacketClass):
		_fields_=AttrList(('guid',StringSZ._c(size=16)),('secblob',StringSZ))
		__slots__=_fields_.keys()
	class NegRespBDSimple(BasePacketClass):
		_fields_=AttrList(('enckey',StringSZ),('domain',WStringZ),('server',WStringZ))
		__slots__=_fields_.keys()
	class SetupNXRespBDESN(BasePacketClass):
		_fields_=AttrList('\x00',('secblob',StringSZ),('os',WStringZ),('lanman',WStringZ),('domain',BrokenWStringZ))
		__slots__=_fields_.keys()+['secblob_size']
	class SetupNXRespBD(BasePacketClass):
		_fields_=AttrList('\x00',('os',WStringZ),('lanman',WStringZ),('domain',BrokenWStringZ))
		__slots__=_fields_.keys()+[]
	class SetupNXWD(BasePacketClass):
		_fields_=AttrList('\xff\x00\x00\x00',('maxbuf',Short,0xffff),('maxmpx',Short),('vcnum',Short,os.getpid()),('sesskey',Int,0),('ansipw_size',Short),('unicodepw_size',Short),('rsrv',Int,0),('capa',CapaFlags))
		__slots__=_fields_.keys()
	class SetupNXBD(BasePacketClass):
		_fields_=AttrList(('ansipw',StringSZ),('unicodepw',StringSZ),'\x00',('user',WStringZ),('domain',WStringZ),('os',WStringZ),('lanman',WStringZ))
		__slots__=_fields_.keys()+['ansipw_size','unicodepw_size']
	class SetupNXRespWDSimple(BasePacketClass):
		_fields_=AttrList('\xff\x00',('nxoff',Short),('action',Flags.mk('asguest',Short)))
		__slots__=_fields_.keys()
	class SetupNXRespWDESN(BasePacketClass):
		_fields_=AttrList('\xff\x00',('nxoff',Short),('action',Flags.mk('asguest',Short)),('secsize',Short))
		__slots__=_fields_.keys()
	class TConXWD(BasePacketClass):
		_fields_=AttrList('\xff\x00',('xoff',Short,0),('flags',Short),('pwlen',Short))
		__slots__=_fields_.keys()
	class TConXBD(BasePacketClass):
		_fields_=AttrList(('passwd',StringSZ),('path',WStringZ),('service',StringZ))
		__slots__=_fields_.keys()
	class NTCreateNXWD(BasePacketClass):
		_fields_=AttrList('\xff\x00',('xoff',Short,0),'\x00',('fname_size',Short),('crflg',Flags.mk('? xoplock boplock createdir extresp',Int)),('rfid',Int,0),('amask',AMaskFlags),('asize',Quad),('fattr',FileAttrFlags),('shacc',ShAccFlags),('dispos',Int),('cropts',CrOptsFlags),('impers',Int),('secflags',Flags.mk('ctxtrack effonly')))
		__slots__=_fields_.keys()
	class NTCreateNXWDResp(BasePacketClass):
		_fields_=AttrList('\xff\x00',('xoff',Short,0),('oplock',Byte),('fid',Short),('cract',Int),('crtime',Quad),('acctime',Quad),('wrtime',Quad),('chtime',Quad),('fattr',FileAttrFlags),('asize',Quad),('eof',Quad),('ftype',Short),('ipcstate',Short),('isdir',Byte))
		__slots__=_fields_.keys()
	class NTCreateNXBD(BasePacketClass):
		_fields_=AttrList('\x00',('fname',WStringZ))
		__slots__=_fields_.keys()
	class TransReqWD(BasePacketClass):
		_fields_=AttrList(
			('tpc',Short,0),('tdc',Short),('mpc',Short,0),
			('mxdc',Short,4280),('mxsc',Byte,0),'\x00',('flags',Flags.mk('dtid owt',Short),0),
			('timeout',Int,0),'\x00\x00',('pc',Short,0),('param_offset',Short),
			('dc',Short),('data_offset',Short),('sc',Byte),'\x00',
			('function',Short,0x26),('fid',Short))
		__slots__=_fields_.keys()
		def get_dc(self):
			return self.tdc
	class TransRespWD(BasePacketClass):
		_fields_=AttrList(
			('tpc',Short),('tdc',Short),'\x00\x00',('pc',Short),
			('param_offset',Short),('param_displace',Short),('data_count',Short),('data_offset',Short),
			('data_displace',Short),('sc',Byte),'\x00')
		__slots__=_fields_.keys()
		def choose_bdata(self,smbpkt,*args):
			print "choose_bdata:",(self,smbpkt,args)
			class TransRespBD(BasePacketClass):
				_fields_=AttrList('\x00',('dce',DCEBindReply))
				__slots__=_fields_.keys()
			return TransRespBD
	class TransReqBD(BasePacketClass):
		_fields_=AttrList('\x00',('name',WStringZ,'\\PIPE\\'),('data',StringSZ))
		__slots__=_fields_.keys()

class SMBPacket(BasePacketClass):
	_t_flags=Flags.mk('lock rcvbuf ? icase canon oplock notify response')
	_t_flags2=Flags.mk('ln_ok ea secsig ?  ? ? ln_use ?   ? ? ? esn  dfs roe nterr unicode')

	def get_wdata_size(self): return self.wct*2
	def get_bdata_size(self): return len(self.bdata)
	def get_wct(self):
		l=len(self.wdata)
		if l%2: raise ValueError,"len(wdata)%2 != 0"
		return l/2

	def choose_wdata(self,data,offset=None,size=None):
		try:
			if self.flags.response:
				if self.cmd.name=='negprot': return SmbCmd.NegRespWD
				if self.cmd.name=='setupnx':
					if self.flags2.esn: return SmbCmd.SetupNXRespWDESN
					else: return SmbCmd.SetupNXRespWDSimple
				if self.cmd.name=='ntcreatenx': return SmbCmd.NTCreateNXWDResp
				if self.cmd.name=='trans': return SmbCmd.TransRespWD
			else:
				if self.cmd.name=='setupnx':
					if not self.flags2.esn: return SmbCmd.SetupNXWD
		except AttributeError,e:
			print "AttributeError:",e
		return StringSZ

	def choose_bdata(self,data,offset=None,size=None):
		try:
			if self.flags.response:
				if self.cmd.name=='negprot':
					if self.flags2.esn: return SmbCmd.NegRespBDESN
					else: return SmbCmd.NegRespBDSimple._c(enckey_size=self.wdata.keysize)
				elif self.cmd.name=='setupnx':
					if self.flags2.esn: return SmbCmd.SetupNXRespBDESN._c(secblob_size=self.wdata.secsize)
					else: return SmbCmd.SetupNXRespBD
				elif self.cmd.name=='trans':
					return self.wdata.choose_bdata(self)
			else:
				if self.cmd.name=='setupnx':
					if not self.flags2.esn: return SmbCmd.SetupNXBD._c(ansipw_size=self.wdata.ansipw_size,unicodepw_size=self.wdata.unicodepw_size)
		except AttributeError,e:
			import traceback
			traceback.print_stack()
			print type(e).__name__,e
			pass
		return StringSZ
	def _repr(self):
		try: return '%s %s'%(self.cmd._repr(),['req','resp'][self.flags.response])
		except AttributeError: return ''

	@classmethod
	def mknegprot(cls,esn=False):
		flags2=cls._t_flags2(cls._fields_.defaults['flags2'])
		flags2.esn=esn
		return cls(cmd=0x72,flags2=flags2,tid=0,mpx=1,wdata=StringSZ(''),bdata=StringSZ('\x02NT LM 0.12\x00'))
	@classmethod
	def mklogin_anon(cls,mpx):
		bd=SmbCmd.SetupNXBD(ansipw='',unicodepw='',user='',domain='',os='Unix',lanman='plib')
		wd=SmbCmd.SetupNXWD(maxmpx=mpx,ansipw_size=0,unicodepw_size=0,capa=CapaFlags('unicode lg ntsmb ntst dfs lg_rdx lg_wrx'.split()))
		return cls(cmd=0x73,tid=0,mpx=mpx,wdata=wd,bdata=bd)
	@classmethod
	def mklogin(cls,mpx,srvchl,user,passwd,domain):
		ntlmv2=NTLMv2Resp(srvchl=srvchl,user=user,passwd=passwd,dest=domain)
		bd=SmbCmd.SetupNXBD(ansipw=ntlmv2.lmv2resp,unicodepw=ntlmv2,user=user,domain=domain,os='Unix',lanman='plib')
		wd=SmbCmd.SetupNXWD(maxmpx=mpx,ansipw_size=24,unicodepw_size=len(ntlmv2),capa=CapaFlags('unicode lg ntsmb ntst dfs lg_rdx lg_wrx'.split()))
		return cls(cmd=0x73,tid=0,mpx=mpx,wdata=wd,bdata=bd)
	@classmethod
	def mkntcreatnx(cls,mpx,uid,tid,fname,amask,crflg=0,asize=0,fattr=0):
		bd=SmbCmd.NTCreateNXBD(fname=fname)
		wd=SmbCmd.NTCreateNXWD(fname_size=len(bd)-2,crflg=crflg,amask=amask,asize=asize,fattr=0,shacc=3,dispos=1,cropts=0,impers=2,secflags=0)
		return cls(cmd=0xa2,uid=uid,tid=tid,mpx=mpx,wdata=wd,bdata=bd)

	_fields_=AttrList('\xffSMB',('cmd',SmbCmd),('status',Int,0),('flags',_t_flags,8),('flags2',_t_flags2,0xc001),('pidh',Short,0), ('signature',StringSZ._c(size=8),'\x00'*8),('rsrv',Short,0),('tid',Short),('pid',Short,os.getpid()),('uid',Short,0), ('mpx',Short),('wct',Byte),('wdata',choose_wdata),('bdata_size',Short),('bdata',choose_bdata))
	__slots__=_fields_.keys()+['wdata_size']

class NetBIOSMessage(BasePacketClass):
	_fields_=AttrList(('msg_size',IntBE),('msg',SMBPacket))
	__slots__=_fields_.keys()

class NTError(ProtocolError): pass
class NTLogonFailure(NTError):
	errcode=0xc000006d
class NTAccountRestriction(NTError):
	errcode=0xc000006e
class NTAccountDisabled(NTError):
	errcode=0xc0000072
class NTBadDeviceType(NTError):
	errcode=0xc00000cb
class NTAccessDenied(NTError):
	errcode=0xc0000022

NTERR=dict([(x.errcode,x) for x in [NTLogonFailure,NTAccountRestriction,NTAccountDisabled,NTBadDeviceType,NTAccessDenied]])

class DCEUUID(BasePacketClass):
	_fields_=AttrList(('uuid1',Int),('uuid2',Short),('uuid3',Short),('uuid4',QuadBE),('major',Short,0),('minor',Short,0))
	__slots__=_fields_.keys()+['uuid','ver']
	def set_uuid(self,val):
		v=val.split('-')
		self.uuid1,self.uuid2,self.uuid3=map(lambda x: int(x,16),v[0:3])
		self.uuid4=int(''.join(v[3:]),16)
	def set_ver(self,val):
		if type(val) in (str,unicode):
			val=map(int,val.split('.'))
		self.major,self.minor=val
	def _repr(self):
		return '%08x-%04x-%04x-%04x-%06x %d.%d'%(int(self.uuid1),int(self.uuid2),int(self.uuid3),int(self.uuid4)>>56,int(self.uuid4)&((1<<56)-1),int(self.major),int(self.minor))

class DCETransCtx(BasePacketClass):
	_fields_=AttrList(('id',Short,0),('items_count',Short),('items',ArrayAttr._c(dtype=DCEUUID)),('syntax',DCEUUID,DCEUUID(uuid='8a885d04-1ceb-11c9-9fe8-08002b104860',ver="2.0")))
	__slots__=_fields_.keys()

class DCEBase(BasePacketClass):
	_fields_=AttrList(('ver',Byte,5),('ver_min',Byte,0),('pkttype',Byte),
		('flags',Flags.mk('first last cancel ? mpx noexec maybe object'),3),
		('drep',Int,0x10),('frag_size',Short),('auth_size',Short,0),('callid',Int),
		('data',StringSZ))
	__slots__=_fields_.keys()
	def get_frag_size(self):
		return len(self)

class DCECall(BasePacketClass):
	pass
		
class LsarOpenPolicyRequest(DCECall):
	opcode=6
	_fields_=AttrList(('server',StringSZ))
	

class DCEBindPacket(BasePacketClass):
	_fields_=DCEBase._fields_.dup(pkttype='\x0b',data=[('max_xmit',Short,4280),('max_rcv',Short,4280),('accgrp',Int,0),
		('items_count',Int),('items',ArrayAttr._c(dtype=DCETransCtx))])
	__slots__=_fields_.keys()
	def get_frag_size(self):
		return self._offsetof('items')+len(self.items)

class DCEBindReply(BasePacketClass):
	_fields_=DCEBase._fields_.dup(data=[('max_xmit',Short),('max_rcv',Short),('accgrp',Int),
		('secaddr_size',Short),('secaddr',StringZ),'\x00\x00',('items_count',Int),('items',ArrayAttr._c(dtype=DCETransCtx))])
	__slots__=_fields_.keys()

class DCECallContext(DynamicAttrClass):
	_tuple_attrs=['file','createpacket']
	__slots__=_tuple_attrs+['ctxid','connection']
	def get_connection(self): return self.file.connection
	def get_ctxid(self): return self.createpacket.bdata.items[0].id
		

	

class SmbFile(DynamicAttrClass):
	_tuple_attrs=['tree','createpacket']
	__slots__=_tuple_attrs+['fid','connection','callid','contexts','recv']
	def get_fid(self): return self.createpacket.wdata.fid
	def get_connection(self): return self.tree.connection
	def next_callid(self): return self.callid+1
	def get_callid(self): return 0
	def get_contexts(self): return {}
	def bind_dcerpc(self,uuid,ver='0.0'):
		bindpkt=DCEBindPacket(callid=self.next_callid(),
			items=[DCETransCtx(id=0,items=[DCEUUID(uuid=uuid,ver=ver)])])
		recv=self.connection.send_recv_nx('trans',self.tree.tid,
			SmbCmd.TransReqWD(sc=2,tdc=len(bindpkt),fid=self.fid,param_offset=82,data_offset=82),
			SmbCmd.TransReqBD(data=bindpkt))
		self.contexts[int(bindpkt.items[0].id)]=recv
		return DCECallContext(self,recv)

class SmbTree(DynamicAttrClass):
	_tuple_attrs=['connection','createpacket','files']
	__slots__=_tuple_attrs+['tid']
	def get_tid(self): return int(self.createpacket.tid)
	def get_files(self): return {}
	def ntcreate(self,fname):
		recv=self.connection.send_recv_nx('ntcreatenx',self.tid,
			SmbCmd.NTCreateNXWD(fname_size=len(fname)*2,crflg=0,amask=0x2019f,asize=0,fattr=0,shacc=3,dispos=1,cropts=0,impers=2,secflags=0),
			SmbCmd.NTCreateNXBD(fname=fname))
		self.files[recv.wdata.fid]=SmbFile(self,recv)
		return self.files[recv.wdata.fid]

class SmbConnection(DynamicAttrClass):
	_defaults=dict(user='',passwd='',port=445,logged_in=False)
	_tuple_attrs=['host','user','passwd','domain']
	__slots__=['host','sock','uid','server','mpx','negresp','loginresp','domain','trees']+_defaults.keys()
	def get_trees(self): return {}
	def get_domain(self): return self.negresp.bdata.domain.value
	def get_server(self):
		try: return self.negresp.bdata.server.value
		except ValueError: return self.host
	def get_uid(self): return int(self.loginresp.uid)
	def nb_send_recv(self,sendmsg):
		self.sock.send(str(NetBIOSMessage(msg=sendmsg)))
		recv=NetBIOSMessage(self.sock.recv())
		if not recv.msg.status==0:
			raise NTERR.get(int(recv.msg.status),NTError),(recv.msg.status,recv.msg)
		return recv.msg
	def connect(self):
		self.sock=TcpSock((self.host,self.port))
		self.negresp=self.nb_send_recv(SMBPacket.mknegprot())
		self.mpx=int(self.negresp.mpx)
	def next_mpx(self):
		self.mpx=self.mpx+1
		return self.mpx
	def login(self,user=None,passwd=None,domain=None):
		if user is None: user=self.user
		if passwd is None: user=self.passwd
		if domain is None: user=self.domain
		if self.user=='':
			self.loginresp=self.nb_send_recv(SMBPacket.mklogin_anon(self.next_mpx()))
		else:
			self.loginresp=self.nb_send_recv(SMBPacket.mklogin(self.next_mpx(),self.negresp.bdata.enckey,self.user,self.passwd,self.domain))
		self.logged_in=True
	def tree_connect(self,share,service=None):
		if service is None:
			if share.lower()=='ipc$': service='IPC'
			else: service='?????'
		resp=self.send_recv_nx('tconx',0,
			SmbCmd.TConXWD(flags=8,pwlen=1),
			SmbCmd.TConXBD(passwd='\x00',path='\\\\%s\\%s'%(self.server,share),service=service))
		self.trees[resp.tid]=SmbTree(self,resp)
		return self.trees[resp.tid]
	def send_recv_nx(self,cmd,tid,wdata,bdata):
		return self.nb_send_recv(SMBPacket(cmd=SmbCmd(cmd),uid=self.uid,tid=tid,mpx=self.next_mpx(),wdata=wdata,bdata=bdata))

if __name__=='__main__':
	import sys
	import user
	from netutil import TcpSock
	args=dict(host=sys.argv[1])
	if ':' in args['host']:
		host,port=args['host'].split(':')
		args['host'],args['port']=host,int(port)
	try: args['user'],args['passwd']=sys.argv[2:4]
	except ValueError: pass
	s=SmbConnection(**args)
	s.connect()
	#s.login()
	#ipc=s.tree_connect('IPC$').ntcreate('\\lsarpc')
	#lsa=ipc.bind_dcerpc('12345778-1234-abcd-ef00-0123456789ab')
