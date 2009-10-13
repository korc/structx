#!/usr/bin/python

from packetlib import *
from ber import BERTypeField,BERPacket,UniversalTag,TagClass,BERIntPrim

AppTags=Enum.mk("BindRequest BindResponse UnbindRequest SearchRequest SearchResponse ModifyRequest ModifyResponse AddRequest AddResponse DelRequest DelResponse ModifyRDNRequest ModifyRDNResponse CompareRequest CompareResponse AbandonRequest")

class LDAPTypeField(BERTypeField):
	def get_tag(self): 
		if self.tagclass.name=='application': return AppTags(self.value&0x1f)
		else: return BERTypeField.get_tag(self)

class LDAPPacket(BERPacket):
	_fields_=BERPacket._fields_.dup(tf=('tf',LDAPTypeField))
	__slots__=["msgnr","errmsg","payload"]
	def get_msgnr(self): return self.data[0].data
	def set_errmsg(self,value): self.data[1].data[2].data=value
	def get_payload(self): return self.data[1].data
	@classmethod
	def mk(cls,msgnr,pkttype,payload):
		return cls(tf=BERTypeField.mk("SEQ",True),data=LDAPPktArr([BERIntPrim(int(msgnr)),
			LDAPPacket(tf=LDAPTypeField.mk(AppTags(pkttype),True,"application"),data=LDAPPktArr(payload))]))
		

class LDAPPktArr(ArrayAttr):
	dtype=LDAPPacket
	__slots__=[]

class LDAPSession(object):
	def __init__(self,**kwargs):
		for k,v in kwargs.iteritems(): setattr(self,k,v)
	def bind_request(self,name='',simple=''):
		self.bindpkt=LDAPPacket.mk(1,"BindRequest",[
			BERIntPrim(3),
			LDAPPacket(tf=LDAPTypeField.mk("OCTETSTRING"),data=name),
			LDAPPacket(tf=LDAPTypeField(tagclass=TagClass("ctx"),value=0),data=simple),
		])
		return self.bindpkt
	def bind_response(self):
		msg_nr=1
		code=0
		errmsg=''
		matched_dn=''
		return LDAPPacket(tf=BERTypeField.mk("SEQ",True),data=ArrayAttr._c(dtype=BERPacket)([
			BERPacket(tf=BERTypeField.mk("INTEGER"),data=self.bindpkt.get_msgnr()),
			BERPacket(tf=LDAPTypeField.mk(AppTags("BindResponse"),True,"application"),data=ArrayAttr._c(dtype=BERPacket)([
				BERPacket(tf=BERTypeField.mk("ENUM"),data=code),
				BERPacket(tf=BERTypeField.mk("OCTETSTRING"),data=matched_dn),
				BERPacket(tf=BERTypeField.mk("OCTETSTRING"),data=errmsg),
			])),
		]))
