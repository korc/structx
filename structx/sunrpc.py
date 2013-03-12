#!/usr/bin/python

from structx.packetlib import BasePacketClass, AttrList, IntBE, Enum, StringSZ,\
    ArrayAttr
import random, os, time
import socket
import sys


class RpcString(StringSZ):
    def _init_new(self,data):
        self.value=data
    def _init_parse(self,data,data_offset,data_size):
        str_size=IntBE(data[data_offset:data_offset+4], 0).value
        if data_size is not None and str_size>(data_size-4): raise ValueError("Data size mismatch")
        self.value=data[data_offset+4:data_offset+4+str_size]
    def __len__(self):
        try: return self.size
        except AttributeError:
            data_size=len(self.value)
            return 4+data_size+(4-data_size%4)%4
    def __str__(self):
        data_size=len(self.value)
        return "%s%s%s"%(IntBE(data_size), self.value, "\0"*((4-data_size%4)%4))

class RpcAuthUnix(BasePacketClass):
    _fields_=AttrList(('stamp', IntBE), ('machine', RpcString), ('uid', IntBE), ('gid', IntBE), ('gids_count', IntBE), ('gids', ArrayAttr._c(dtype=IntBE)))
    def get_stamp(self): return int(time.time())
    def get_uid(self): return os.getuid()
    def get_gid(self): return os.getgid()
    def get_hostname(self): return os.uname()[1]
    def get_gids(self): return [IntBE(os.getgid())]
    def get_gids_count(self): return self.gids.count
    def get_machine(self): return RpcString(self.hostname)

class RpcAuth(BasePacketClass):
    _fields_=AttrList(('flavor', IntBE, 0), ('data_size', IntBE), ('data', StringSZ, ''))

class RpcReply(BasePacketClass):
    _fields_=AttrList(('xid', IntBE), ('msg_type', Enum.mk("call reply", IntBE)), ('replystat', IntBE), ('verifier', RpcAuth), ('state_accept', IntBE), ('data', StringSZ, ''))
    def get_msg_type(self): return 1
    def get_verifier(self): return RpcAuth()

class RpcCall(RpcReply):
    _fields_=RpcReply._fields_.dup(
        replystat=[('rpc_ver', IntBE, 2), ('prog', IntBE), ('ver', IntBE), ('proc', IntBE), ('creds', RpcAuth)],
        state_accept=[])
    def get_msg_type(self): return 0
    def get_xid(self): return random.randint(0,(1<<32)-1)
    def get_creds(self): return RpcAuth()

class RpcGetPort(BasePacketClass):
    _fields_=AttrList(('prog',IntBE), ('ver', IntBE), ('proto', Enum.mk('', IntBE, tcp=6, udp=17)), ('port', IntBE, 0))

class RpcTcp(BasePacketClass):
    _fields_=AttrList(('frag_hdr', IntBE), ('data', RpcReply))
    def get_frag_hdr(self):
        return (1<<31) | len(self.data)

def parse_export_reply(data):
    ret={}
    idx=0
    while True:
        has_data=IntBE(data, idx)
        idx+=len(has_data)
        if has_data==0: break
        key=RpcString(data, idx)
        grp_a=ret[key.value]=[]
        idx+=len(key)
        while True:
            has_group=IntBE(data, idx)
            idx+=len(has_group)
            if has_group==0: break
            grp=RpcString(data, idx)
            grp_a.append(grp.value)
            idx+=len(grp)
    return ret

def _sr_udp(addr, **params):
    s=socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    s.sendto(str(RpcCall(**params)), addr)
    data,addr_r=s.recvfrom(8192)
    if addr_r!=addr: print >>sys.stderr,"Answer from wrong host:",addr_r
    s.close()
    return RpcReply(data,0)

def get_mount_port(host, proto='udp'):
    resp=_sr_udp((host,111), prog=100000, ver=2, proc=3, data=RpcGetPort(prog=100005, ver=3, proto=proto))
    return IntBE(str(resp.data), 0).value

def get_exports(host, port=None):
    if port is None: port=get_mount_port(host)
    resp=_sr_udp((host,port), prog=100005, ver=3, proc=5)
    return parse_export_reply(str(resp.data))
