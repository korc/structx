#!/usr/bin/python

from packetlib import *

def calc_csize(datasize): return (8+datasize+(8-(datasize%8))%8)/8
def calc_dsize(chunksize): return 8*chunksize-8

class HeapChunk(BasePacketClass):
	_fields_=AttrList(
		('csize',Short),('psize',Short),
		('segnr',Byte,0),('flags',Flags.mk('busy ? ? va last')),
		('index',Byte,0),('tags',Byte,0),
		('data',StringSZ))
	__slots__=_fields_.keys()
	def get_csize(self): return calc_csize(len(self.data))

class FreeChunk(HeapChunk):
	_fields_=HeapChunk._fields_.dup(data=[('blink',Int),('flink',Int)],tags=[('mask',Byte)])
	__slots__=_fields_.keys()

if __name__=='__main__':
    import user
