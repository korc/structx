from structx.crc import crc16_ccitt_seed
from structx.packetlib import BasePacketClass, AttrList, Flags, ArrayAttr, Short, \
    Byte, StringSZ, Enum, Quad

IEEE802154_CRC_SEED=0x0000
IEEE802154_CRC_XOROUT=0xFFFF

def calc_crc(data):
    return crc16_ccitt_seed(data, IEEE802154_CRC_SEED) ^ IEEE802154_CRC_XOROUT

class IntBitVal(object):
    __slots__=["start", "stop", "wrap_type"]
    def __init__(self, start, stop, wrap_type=int):
        self.start=start
        self.stop=stop
        self.wrap_type=wrap_type
    def __get__(self, instance, owner):
        if instance is None: return self
        return self.wrap_type(instance[self.start:self.stop])
    def __set__(self, instance, value):
        instance[self.start:self.stop]=int(value)

class IEEE802154Packet(BasePacketClass):
    __slots__=[]
    class Control(Flags.mk("? ? ? security pending ack_req intra_pan", Short)):
        __slots__=[]
        type=IntBitVal(0, 3, Enum.mk("? data ack", Byte, "FrameType"))
        dst_mode=IntBitVal(10,12)
        ver=IntBitVal(12,14)
        src_mode=IntBitVal(14,16)
    dtype=StringSZ
    def choose_data(self, data, offset=None, size=None):
        if (data and offset is None) or self.ctrl.type.name=="data":
            return self.dtype
        else: return StringSZ._c(size=0) 
    def choose_dst(self, data, offset=None, size=None):
        if (data and offset is None) or self.ctrl.dst_mode==2: return Short
        else: return StringSZ._c(size=0)
    def choose_src(self, data, offset=None, size=None):
        if (data and offset is None) or self.ctrl.src_mode==2: return Short
        else: return StringSZ._c(size=0)
    def choose_dst_pan(self, data, offset=None, size=None):
        if (data and offset is None) or self.ctrl.intra_pan: return Short
        else: return StringSZ._c(size=0)
    _fields_=AttrList(("ctrl", Control), ("seq", Byte), ("dst_pan", choose_dst_pan), 
        ("dst", choose_dst), ("src", choose_src), ("data", choose_data), ("fcs", Short))
    def get_data_size(self):
        return len(self)-sum(map(len,[self.dst_pan, self.dst, self.src]))-2-1-2
    def get_fcs(self):
        return calc_crc("".join(map(lambda x: str(getattr(self, x)), ["ctrl", "seq", "dst_pan", "dst", "src", "data"])))

class ZBFrame(BasePacketClass):
    __slots__=[]
    class Control(Flags.mk("? ? ? ? ? ? ? ?  multicast security src_route ext_dst ext_src", Short)):
        __slots__=[]
        type=IntBitVal(0, 2, Enum.mk("data command", Byte, "FrameType"))
        ver=IntBitVal(2, 6)
        discovery=IntBitVal(6, 8)
    class SrcRoute(BasePacketClass):
        class RouteRelay(BasePacketClass):
            __slots__=[]
            _fields_=AttrList(("idx", Byte), ("addr", Short))
        __slots__=[]
        _fields_=AttrList(("route_count", Byte), ("route", ArrayAttr._c(dtype=RouteRelay)))
    def choose_dst64(self, data, offset=None, size=None):
        if (data and offset is None) or self.ctrl.ext_dst: return Quad
        else: return StringSZ._c(size=0)
    def choose_src64(self, data, offset=None, size=None):
        if (data and offset is None) or self.ctrl.ext_src: return Quad
        else: return StringSZ._c(size=0)
    def set_src64(self, v):
        self.ctrl.ext_src=True if v else False
        return v
    def set_dst64(self, v):
        self.ctrl.ext_dst=True if v else False
        return v
    def choose_src_route(self, data, offset=None, size=None):
        if (data and offset is None) or self.ctrl.src_route: return self.SrcRoute
        else: return StringSZ._c(size=0)
    def set_src_route(self, v):
        self.ctrl.src_route=True if v else False
        return v
    _fields_=AttrList(("ctrl", Control), ("dst", Short), ("src", Short), ("radius", Byte),
        ("seq", Byte), ("dst64", choose_dst64), ("src64", choose_src64), ("src_route", choose_src_route), ("data", StringSZ))

class ZBAPSWriteAttr(BasePacketClass):
    __slots__=[]
    AType=Enum.mk("", Byte, "AttrType", enum8bit=0x30, boolean=0x10)
    _fields_=AttrList(("attrnum", Short), ("atype", AType), ("data", StringSZ))

class ZBAPSFrame(BasePacketClass):
    __slots__=[]
    class Control(Flags.mk("? ? ? ?  ? security ack_req ext_hdr", Byte)):
        __slots__=[]
        type=IntBitVal(0,2, Enum.mk("data", Byte, "FrameType"))
        delivery=IntBitVal(2,4, Enum.mk("unicast", Byte, "DeliveryMode"))
    _fields_=AttrList(("ctrl", Control), ("dst", Byte), ("cluster", Short), ("profile", Short), ("src", Byte), ("counter", Byte), ("data", StringSZ))

class ZBLibraryFrame(BasePacketClass):
    __slots__=[]
    class FrameControl(Flags.mk("? ? ms dir ddr", Byte)):
        __slots__=[]
        type=IntBitVal(0,2, Enum.mk("profwide", Byte, "FrameType"))
    CommandType=Enum.mk("? ? write_attr")
    _fields_=AttrList(("ctrl", FrameControl), ("seq", Byte), ("cmd", CommandType), ("data", StringSZ))

if __name__ == '__main__':
    import user #@UnusedImport
    import structx.ethernet
    class PCapFile(structx.ethernet.PCapFile):
        __slots__=[]
        def choose_pcap_packet(self,data,offset=None,size=None):
            if self.network.name=='ieee802_15_4':
                return ArrayAttr._c(dtype=structx.ethernet.PCapPacket._c(dtype=IEEE802154Packet))
            else:
                return super(PCapFile, self).choose_pcap_packet(data, offset, size)
        _fields_=structx.ethernet.PCapFile._fields_.dup(data=("data",choose_pcap_packet))

