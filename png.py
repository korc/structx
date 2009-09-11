#!/usr/bin/python

from packetlib import *

crc_table=None
def get_crc_table():
	global crc_table
	if crc_table is None:
		crc_table=[]
		for c in range(256):
			for k in range(8):
				if c&1: c=0xedb88320^(c>>1)
				else: c=c>>1
			crc_table.append(c)
	return crc_table

def calc_crc(data,crc=0xffffffff):
	tbl=get_crc_table()
	for byte in data:
		crc=tbl[(crc^ord(byte))&0xff]^(crc>>8)
		crc=crc&0xffffffff
	return crc^0xffffffff

class ColorType(Enum):
	__slots__=[]
	enum=Enum.mkenum('grayscale ? rgb palette gray_alpha ? rgba')

class IHdrData(BasePacketClass):
	_fields_=AttrList(('width',IntBE),('height',IntBE),('bits',Byte),('colortype',ColorType),('compression',Enum.mk('Deflate')),('filter',Byte),('interlace',Byte))
	__slots__=_fields_.keys()

class TextData(BasePacketClass):
	_fields_=AttrList(('keyword',StringZ),('text',StringSZ))
	__slots__=_fields_.keys()
	def _repr(self): return '%r=%r'%(self.keyword.value,self.text.value)

class PhysData(BasePacketClass):
	_fields_=AttrList(('ppux',IntBE),('ppuy',IntBE),('unit',Enum.mk('unknown metre')))
	__slots__=_fields_.keys()
	def _repr(self): return '%d/%d %s'%(self.ppux,self.ppuy,self.unit.name)

class TimeData(BasePacketClass):
	_fields_=AttrList(('year',ShortBE),('month',Byte),('day',Byte),('hour',Byte),('minute',Byte),('second',Byte),)
	__slots__=_fields_.keys()
	def _repr(self): return '%02d-%02d-%02d %02d:%02d:%02d'%(self.year,self.month,self.day,self.hour,self.minute,self.second)

class Chunk(BasePacketClass):
	def choose_data(self,data,data_offset=None,data_size=None):
		if self.code=='IHDR': return IHdrData
		elif self.code=='tEXt': return TextData
		elif self.code=='pHYs': return PhysData
		elif self.code=='tIME': return TimeData
		else: return StringSZ
	def _repr(self): return str(self.code)
	def calc_crc(self): return calc_crc('%s%s'%(self.code,self.data))
	def get_crc(self): return IntBE(self.calc_crc())
	_fields_=AttrList(('data_size',IntBE),('code',StringSZ._c(size=4)), ('data',choose_data), ('crc',IntBE))
	__slots__=_fields_.keys()

class PNGImage(BasePacketClass):
	_fields_=AttrList('\x89PNG\r\n\x1a\n',('chunks',ArrayAttr._c(dtype=Chunk,end=Chunk(data='',code='IEND'))))
	__slots__=_fields_.keys()
	def _repr(self): return '%dx%d %s'%(self.chunks[0].data.width,self.chunks[0].data.height,self.chunks[0].data.colortype.name)

if __name__=='__main__':
	import sys,user
	p=PNGImage(open(sys.argv[1]).read())
