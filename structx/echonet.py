#!/usr/bin/python

from structx.packetlib import BasePacketClass, AttrList, Byte, Short, StringSZ,\
    Enum, ArrayAttr
from structx.ethernet import TCP, UDP, PCapNGFile, Ether, IPv4


class ESVPropertyType(Enum.mk("", Byte,
    err_status=0x88, vendor_code=0x8a, location_code=0x8b,
    prod_code=0x8c, prod_serial=0x8d, prod_date=0x8e, info_prop_map=0x9d,
    set_prop_map=0x9e, get_prop_map=0x9f)): pass

class ESVProperty(BasePacketClass):
    _fields_=AttrList(('epc', ESVPropertyType),('data_size', Byte), ('data', StringSZ))

class ESVType(Enum.mk("", Byte,
    SetI=0x60, SetC=0x61, Get=0x62, INF_REQ=0x63, SetGet=0x6e,
    Set_Res=0x71, Get_Res=0x72, INF=0x73, INFC=0x74, INFC_Res=0x7a,
    SetGet_Res=0x7e, SetI_SNA=0x50, SetC_SNA=0x51, Get_SNA=0x52, INF_SNA=0x53,
    SetGet_SNA=0x5E)): pass

class EData(BasePacketClass):
    _fields_=AttrList(
        ("seoj", StringSZ._c(size=3)), ("deoj", StringSZ._c(size=3)),
        ("esv", ESVType), ("props_count", Byte), ('props', ArrayAttr._c(dtype=ESVProperty))
    )

class ECommonFrame(BasePacketClass):
    _fields_=AttrList(
        ("ehd1", Enum.mk("", Byte, EchonetLite=0x10), 0x10),
        ("ehd2", Enum.mk("", Byte, STD=0x81, ARB=0x82)),
        ("tid", Short), ("data", EData)
    )

def is_eframe(obj, data, data_offset, data_size):
    return (obj.dport==3610 or obj.sport==3610) and data_size>0

TCP.register_atype("data", (is_eframe, ECommonFrame))
UDP.register_atype("data", (is_eframe, ECommonFrame))

def parse_pcap(pcap_file):
    pcap=PCapNGFile(pcap_file)
    ebp_count=0
    for block in pcap.blocks:
        if block.type.name=="EBP":
            ebp_count+=1
            ether=Ether(str(block.data.data))
            if (isinstance(ether.data, IPv4)
                    and isinstance(ether.data.data, (TCP, UDP))
                    and isinstance(ether.data.data.data, ECommonFrame)):
                payload=ether.data.data.data
                payload._pcap_frame_number=ebp_count
                payload._ether=ether
                yield payload
            #yield ECommonFrame(str(tcp.data))

if __name__ == '__main__':
    import user, sys
    gen=parse_pcap(open(sys.argv[1]))
    pkt=gen.next()
    print "pkt.pprint():"
    pkt.pprint()
