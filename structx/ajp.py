#!/usr/bin/python

from structx.packetlib import BasePacketClass, AttrList, ShortBE, StringSZ, Enum,\
    Byte, cached_property, ArrayAttr

AJPDataType=Enum.mk("? ? Req RespBody RespHdr RespEnd", Byte, "AJPDataType")
AJPMethod=Enum.mk("? ? GET", Byte, "AJPMethod")
AJPHeaderType=Enum.mk("Unknown", ShortBE, Authorization=0xa005, UserAgent=0xa00e, Host=0xa00b, Accept=0xa001)

class AJPShortString(BasePacketClass):
    _fields_=AttrList(('data_size', Byte), ('data', StringSZ), '\x00')

class AJPString(StringSZ):
    def _init_new(self,data):
        if data is not None: self.value=data
    def _init_parse(self,data,data_offset,data_size):
        self.vsize=ShortBE(data,data_offset)
        if self.vsize.value==0xffff: return
        if data_size is not None and self.vsize.value>(data_size-3):
            raise ValueError("Data size mismatch: %d+3 > %d"%(self.vsize.value, data_size))
        if data[data_offset+self.vsize.value+2]!='\x00':
            raise ValueError("Data does not terminate with null byte")
        self.value=data[data_offset+2:data_offset+2+self.vsize.value]
    def __len__(self):
        try: val=self.value
        except AttributeError: return 2
        return len(val)+3
    @cached_property
    def vsize(self):
        try: val=self.value
        except AttributeError: return ShortBE(0xffff)
        return ShortBE(len(val))
    def __str__(self):
        try: val=self.value
        except AttributeError: return str(self.vsize)
        return "%s%s\x00"%(self.vsize, val)

class AJPHeader(BasePacketClass):
    _fields_=AttrList(
        ('type', AJPHeaderType),
        ('name', [({"type":0xa000}, AJPShortString), ({},StringSZ._c(size=0))]),
        ('data', AJPString),
    )

class AJPRequest(BasePacketClass):
    _fields_=AttrList(
        ('code', AJPDataType, 2),
        ('method', AJPMethod, 2),
        ('http_ver', AJPString, "HTTP/1.1"),
        ('uri', AJPString, "/"),
        ('raddr', AJPString, None),
        ('rhost', AJPString, None),
        ('srv', AJPString, None),
        ('port', ShortBE, 80),
        ('sslp', Byte, 0),
        ('hdr_count', ShortBE),
        ('hdr', ArrayAttr._c(dtype=AJPHeader), []),
        ('\xff')
    )

class AJPRespHdrPair(BasePacketClass):
    _fields_=AttrList(('name', AJPString), ('value', AJPString))

class AJPRespHdr(BasePacketClass):
    _fields_=AttrList(
        ('code', AJPDataType, 4),
        ('status', ShortBE),
        ('message', AJPString),
        ('hdr_count', ShortBE),
        ('hdr', ArrayAttr._c(dtype=AJPRespHdrPair)),
    )

class AJPRespBody(BasePacketClass):
    _fields_=AttrList(
        ('code', AJPDataType, 3),
        ('body', AJPString)
    )

class AJPRespEnd(BasePacketClass):
    _fields_=AttrList(
        ('code', AJPDataType, 5),
        ('reusep', Byte, 1)
    )

class AJPPacket(BasePacketClass):
    def choose_ajp_data(self, data, data_offset=0, data_size=None):
        dtype=AJPDataType(data,data_offset)
        for cls in AJPRequest, AJPRespHdr, AJPRespBody, AJPRespEnd:
            if dtype==cls._fields_["code"].default:
                return cls
        return StringSZ
    _fields_=AttrList(('magic', ShortBE, 0x1234), ('data_size', ShortBE), ('data', choose_ajp_data))
    @classmethod
    def from_socket(cls, sock):
        buf=""
        more_data=True
        while more_data:
            while buf:
                pkt=cls(buf, 0)
                if len(pkt)<=len(buf):
                    yield pkt
                    buf=buf[len(pkt):]
                    if pkt.data.code.value==5:
                        more_data=False
                        break
                else: break
            if more_data:
                d=sock.recv(8192)
                if d=="": break
                buf+=d

def make_request(sock, server_name, url="/", headers=None):
    args={"uri":url, "srv": server_name}
    if headers is not None:
        args["hdr"]=map(lambda name: AJPHeader(name=name, data=headers[name]), headers)
    send_pkt=AJPPacket(data=AJPRequest(**args))
    sock.send(str(send_pkt))
    for pkt in AJPPacket.from_socket(sock):
        yield pkt
