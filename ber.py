#!/usr/bin/python

from packetlib import *

TagClass=Enum.mk("universal application ctx private",Byte,"TagClass")

UniversalTag=Enum.mk("EOC BOOLEAN INTEGER BITSTRING OCTETSTRING NULL OBJECTID ObjDesc EXT REAL ENUM EMBED UTF8Str RELOID UKN14 UKN15 SEQ SET NumStr PrnStr T61Str VidStr IA5Str UTCTime GenTime GraphStr VisStr UnivStr CHARSTR BMPStr",Byte,"UniversalTag")

UnknownTag=Enum.mk("",Byte,"UnknownTag")

PrimComp=Enum.mk("Primval Compound",Byte,"PrimComp")

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
	def get_compound(self): return PrimComp((self.value>>5)&1)
	def set_compound(self,val): self.value=(self.value&0xdf) | (0x20 if val else 0)
	def get_tagclass(self): return TagClass(self.value>>6)
	def set_tagclass(self,val): self.value=(int(val)<<6) | (self.value&0x3f)
	def get_tag(self): 
		if self.tagclass.name=='universal': return UniversalTag(self.value&0x1f)
		else: return UnknownTag(self.value&0x1f)
	def set_tag(self,val): self.value=(self.value&0xe0) | int(val)
	def _repr(self): return '%s %s %s'%(self.tagclass.name,self.compound._repr(),self.tag._repr())
	__slots__=[]
	@classmethod
	def mk(cls,tag,compound=0,tagclass=0):
		if type(tag) in (str,unicode): tag=UniversalTag(tag)
		if type(tagclass) in (str,unicode): tagclass=TagClass(tagclass)
		ret=cls(0)
		ret.tag,ret.compound,ret.tagclass=tag,compound,tagclass
		return ret

class BERPacket(BasePacketClass):
	def choose_data(self,data,offset=None,size=None):
		if self.tf.compound: return ArrayAttr._c(dtype=self.__class__)
		elif isinstance(self.tf.tag,Enum) and self.tf.tag.name in ("INTEGER","ENUM","BOOLEAN"): return IntValSZ._c(le=False)
		return StringSZ
	_fields_=AttrList(('tf',BERTypeField),('data_size',BERInt),('data',choose_data))
	def _repr(self): return self.tf._repr()
	def get_size(self): return len(self.tf)+len(self.data_size)+int(self.data_size)
	__slots__=_fields_.keys()+['size']

class BERIntPrim(BERPacket):
	__slots__=[]
	def get_tf(self): return BERTypeField.mk("INTEGER")
	def _init_new(self,data,*attrs,**kwattrs):
		if type(data) in (int,long): self.data=data
		else: BERPacket._init_new(self,data,*attrs,**kwattrs)
