import unittest
from packetlib import AttrList, Int, BasePacketClass, DynamicAttrClass,\
    CyclicAttributeError

class A(BasePacketClass):
    __slots__=[]
    _fields_=AttrList(('a',Int),('b',Int))
    def get_b(self):
        print "A.get_b run"
        return 10

class B(A):
    __slots__=[]
    _fields_=A._fields_.dup(a=[('a',Int,10)])
    def set_b(self, v):
        print "B.set_b run"
        return v+3
    def set_c(self, v):
        print "B.set_c run"
        self.a=v+2

class C(DynamicAttrClass):
    x=10
    def get_c(self): return self.x+10
    def set_c(self, value):
        self.x=value-10

class D(DynamicAttrClass):
    def get_a(self): return self.b+10
    def get_b(self): return self.a-10

class PropFieldsTestCase(unittest.TestCase):
    png_data='\x89PNG\r\n\x1a\n\x00\x00\x00\rIHDR\x00\x00\x00\x05\x00\x00\x00\x06\x08\x02\x00\x00\x00\x84\x99\xc3\x1c\x00\x00\x00\x01sRGB\x00\xae\xce\x1c\xe9\x00\x00\x00\tpHYs\x00\x00\x0e\xc4\x00\x00\x0e\xc4\x01\x95+\x0e\x1b\x00\x00\x00\x07tIME\x07\xdc\x03\x12\r#\x15\xcf4\x93\xe9\x00\x00\x00\x19tEXtComment\x00Created with GIMPW\x81\x0e\x17\x00\x00\x00dIDAT\x08\xd7c\xe4\xe0`gbb\xfe\xf7\xef?\x13\x13\xc3\xff\xff\xff\x99\xff\xfd\xfb\xcf\xc4\xcc\xc4\xc2\xc2\xc4\xc0\xc8\xc0\xc0\xc0\xc4 ""RZZ\xfa\x0c\x06\x18\x19\x18\x18\x98\x99\x99yxy\xb9D%y\xbf\xbc`````a\x17\x98x\xea\xe3\xff\xefO\xef<|\xcc\xc0\xc0\xc0 \xaa\xef\xf8`n\xb0\x86\x04\xbf\x90\xb0\x04\x00\x0f\x03\x1f\xf3}\xfbs0\x00\x00\x00\x00IEND\xaeB`\x82'
    ether_data='\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x08\x00E\x00\x00>\x8f\x12@\x00@\x11\xad\x9a\x7f\x00\x00\x01\x7f\x00\x00\x01\x87I\x005\x00*\xfe=3Q\x01\x00\x00\x01\x00\x00\x00\x00\x00\x00\x07weather\x04noaa\x03gov\x00\x00\x01\x00\x01'
    def testEther(self):
        from ethernet import Ether
        e=Ether(self.ether_data)
        assert self.ether_data==str(e)
    def testDNS(self):
        import dns, ethernet
        e=ethernet.Ether(self.ether_data)
        dns_data=str(e.data.data.data)
        d=dns.DnsPacket(dns_data)
        assert str(d)==dns_data
    def testBasicClasses(self):
        a,b=A(),B()
        b.c=10
        assert b.a==12
        assert b.b==13
        assert a.b==10
        a.b=10
        assert a.b==10
        b.b=10
        assert b.b==13
    def testReEntrance(self):
        d=D()
        try: d.a
        except Exception,e:
            assert isinstance(e,CyclicAttributeError)
        d=D(a=10)
        assert d.b==0
        assert d.a==10
    def testLdap(self):
        from ldap import LDAPSession
        from ber import BERPacket
        d=LDAPSession().bind_request()
        b=BERPacket(str(d))
        assert str(b)==d
    def testPng(self):
        from png import PNGImage
        p=PNGImage(self.png_data)
        assert self.png_data==str(p)

if __name__=='__main__':
    import user #@UnusedImport
    unittest.main()