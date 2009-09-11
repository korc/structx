#!/usr/bin/python

from packetlib import *

TagClass=Enum.mk("universal application ctx private",Byte)
TagClass.__name__="TagClass"

UniversalTag=Enum.mk("EOC BOOLEAN INTEGER BITSTRING OCTETSTRING NULL OBJECTID ObjDesc EXT REAL ENUM EMBED UTF8Str RELOID UKN14 UKN15 SEQ SET NumStr PrnStr T61Str VidStr IA5Str UTCTime GenTime GraphStr VisStr UnivStr CHARSTR BMPStr",Byte)
UniversalTag.__name__="UniversalTag"

UnknownTag=Enum.mk("",Byte)

PrimConst=Enum.mk("P C",Byte)
PrimConst.__name__="PrimConst"

class BERInt(IntVal):
	def _init_parse(self,data,data_offset,data_size):
		b0=ord(data[data_offset])
		if b0&0x80:
			numbytes=b0&0x7f
			self.value=0
			for idx in range(numbytes):
				self.value=self.value<<8
				self.value=self.value|ord(data[data_offset+1+idx])
		else: self.value=b0
	def get_size(self): return len(self)
	def __len__(self):
		if self.value<0x80: return 1
		ret=1
		val=self.value
		while val>0:
			ret=ret+1
			val=val>>8
		return ret
	def __str__(self):
		if self.value<0x80: return chr(self.value)
		ret=[chr(0x80+len(self)-1)]
		val=self.value
		while val>0:
			ret.insert(1,chr(val&0xff))
			val=val>>8
		return ''.join(ret)
	__slots__=[]

class BERTypeField(Byte):
	def get_pc(self): return PrimConst((self.value>>5)&1)
	def set_pc(self,val): self.value=(self.value&0xdf) | (0x20 if val else 0)
	def get_tc(self): return TagClass(self.value>>6)
	def set_tc(self,val): self.value=(int(val)<<6) | (self.value&0x3f)
	def get_tag(self): 
		if self.tc.name=='universal': return UniversalTag(self.value&0x1f)
		else: return UnknownTag(self.value&0x1f)
	def set_tag(self,val): self.value=(self.value&0xe0) | int(val)
	def _repr(self): return '%s %s %s'%(self.tc.name,self.pc._repr(),self.tag._repr())
	__slots__=[]
	@classmethod
	def mk(cls,tag,pc=0,tc=0):
		if type(tag) in (str,unicode): tag=UniversalTag(tag)
		if type(tc) in (str,unicode): tc=TagClass(tc)
		ret=cls(0)
		ret.tag,ret.pc,ret.tc=tag,pc,tc
		return ret

class BERPacket(BasePacketClass):
	def choose_data(self,data,offset=None,size=None):
		if self.tf.pc: return ArrayAttr._c(dtype=self.__class__)
		elif isinstance(self.tf.tag,Enum) and self.tf.tag.name in ("INTEGER","ENUM","BOOLEAN"): return BERInt
		return StringSZ
	_fields_=AttrList(('tf',BERTypeField),('data_size',BERInt),('data',choose_data))
	def _repr(self): return self.tf._repr()
	__slots__=_fields_.keys()
