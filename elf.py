#!/usr/bin/python

from packetlib import *

PType=Enum.mk('NULL LOAD DYNAMIC INTERP NOTE SHLIB PHDR TLS NUM',Int,
	"PType",LOOS=0x60000000,GNU_EH_FRAME=0x6474e550, GNU_STACK=0x6474e551, GNU_RELRO=0x6474e552, LOSUNW=0x6ffffffa, SUNWBSS=0x6ffffffa, SUNWSTACK=0x6ffffffb, HISUNW=0x6fffffff, HIOS=0x6fffffff, LOPROC=0x70000000, HIPROC=0x7fffffff)

PFlags=Flags.mk('X W R',Int)
PFlags.__name__='PFlags'

class PHeader(BasePacketClass):
	_fields_=AttrList(('ptype',PType),('offset',Int), ('vaddr',Int), ('paddr',Int), ('filesz',Int), ('memsz',Int), ('flags',PFlags), ('align',Int))
	__slots__=_fields_.keys()
	def _repr(self): return "%s@%x"%(self.ptype._repr(),self.vaddr)

DTag=Enum.mk('NULL NEEDED PLTRELSZ PLTGOT HASH DT_STRTAB DT_SYMTAB DT_RELA DT_RELASZ DT_RELAENT DT_STRSZ DT_SYMENT DT_INIT DT_FINI DT_SONAME DT_RPATH DT_SYMBOLIC DT_REL DT_RELSZ DT_RELENT DT_PLTREL DT_DEBUG DT_TEXTREL DT_JMPREL DT_BIND_NOW DT_INIT_ARRAY DT_FINI_ARRAY DT_INIT_ARRAYSZ DT_FINI_ARRAYSZ DT_RUNPATH DT_FLAGS DT_ENCODING DT_PREINIT_ARRAY DT_PREINIT_ARRAYSZ DT_NUM',Int,"DTag",DT_LOOS=0x6000000d, DT_HIOS=0x6ffff000, DT_LOPROC=0x70000000, DT_HIPROC=0x7fffffff, DT_PROCNUM=0x32, DT_VALRNGLO=0x6ffffd00, DT_GNU_PRELINKED=0x6ffffdf5, DT_GNU_CONFLICTSZ=0x6ffffdf6, DT_GNU_LIBLISTSZ=0x6ffffdf7, DT_CHECKSUM=0x6ffffdf8, DT_PLTPADSZ=0x6ffffdf9, DT_MOVEENT=0x6ffffdfa, DT_MOVESZ=0x6ffffdfb, DT_FEATURE_1=0x6ffffdfc, DT_POSFLAG_1=0x6ffffdfd, DT_SYMINSZ=0x6ffffdfe, DT_SYMINENT=0x6ffffdff, DT_VALRNGHI=0x6ffffdff, DT_ADDRRNGLO=0x6ffffe00, DT_GNU_HASH=0x6ffffef5, DT_TLSDESC_PLT=0x6ffffef6, DT_TLSDESC_GOT=0x6ffffef7, DT_GNU_CONFLICT=0x6ffffef8, DT_GNU_LIBLIST=0x6ffffef9, DT_CONFIG=0x6ffffefa, DT_DEPAUDIT=0x6ffffefb, DT_AUDIT=0x6ffffefc, DT_PLTPAD=0x6ffffefd, DT_MOVETAB=0x6ffffefe, DT_SYMINFO=0x6ffffeff, DT_ADDRRNGHI=0x6ffffeff, DT_ADDRNUM=11, DT_VERSYM=0x6ffffff0, DT_RELACOUNT=0x6ffffff9, DT_RELCOUNT=0x6ffffffa, DT_FLAGS_1=0x6ffffffb, DT_VERDEF=0x6ffffffc, DT_VERDEFNUM=0x6ffffffd, DT_VERNEED=0x6ffffffe, DT_VERNEEDNUM=0x6fffffff, DT_AUXILIARY=0x7ffffffd, DT_FILTER=0x7fffffff)

SHType=Enum.mk("NULL PROGBITS SYMTAB STRTAB RELA HASH DYNAMIC NOTE NOBITS REL SHLIB DYNSYM",Int,"SHType",INIT_ARRAY=14,FINI_ARRAY=15,GNUHASH=0x6ffffff6,GNUVER=0x6fffffff,GNUVER_R=0x6ffffffe)
SHFlags=Flags.mk("WRITE ALLOC EXECINSTR",Int,MASKPROC=0xf0000000)

class Elf32_Dyn(BasePacketClass):
	_fields_=AttrList(('tag',DTag),('val',Int))
	__slots__=_fields_.keys()


class Elf32_Shdr(BasePacketClass):
	_fields_=AttrList(("name",Int),("type",SHType),("flags",SHFlags),("addr",Int),("fileoff",Int),("shsize",Int),("link",Int),("info",Int),("addralign",Int),("entsize",Int))
	__slots__=_fields_.keys()
	def _repr(self): return "%s@%x (%x)"%(self.type._repr(),self.addr,self.fileoff)
	@classmethod
	def new(cls,**attrs):
		return cls(**dict(dict(name=0,type=0,flags=0,addr=0,fileoff=0,shsize=0,link=0,info=0,addralign=0,entsize=0),**attrs))
	@classmethod
	def new_strtab(cls,**attrs):
		return cls.new(**dict(dict(type="STRTAB",addralign=1),**attrs))
	@classmethod
	def new_symtab(cls,**attrs):
		return cls.new(**dict(dict(type="SYMTAB",addralign=4,entsize=0x10),**attrs))
	@classmethod
	def new_text(cls,**attrs):
		return cls.new(**dict(dict(type="PROGBITS",flags=["ALLOC","EXECINSTR"],addralign=4,entsize=0x10),**attrs))

Elf32StBind=Enum.mk("LOCAL GLOBAL WEAK",Byte,"Elf32StBind",LOPROC=13,HIPROC=15)
Elf32StType=Enum.mk("NOTYPE OBJECT FUNC SECTION FILE",Byte,"Elf32StType",LOPROC=13,HIPROC=15)

class Elf32_SymInfo(Byte):
	__slots__=[]
	def get_binding(self): return Elf32StBind(self.value>>4)
	def set_binding(self,val): self.value=self.value&0xf | (int(val)<<4)
	def get_type(self): return Elf32StType(self.value&0xf)
	def set_type(self,val): self.value=self.value&0xf0 | int(val)
	def _repr(self): return "%s %s"%(self.binding._repr(),self.type._repr())

class Elf32_Sym(BasePacketClass):
	_fields_=AttrList(('name',Int),('value',Int),('sz',Int),('info',Elf32_SymInfo),('other',Byte),('shndx',Short))
	__slots__=_fields_.keys()
	@classmethod
	def new(cls,**attrs):
		return cls(**dict(dict(name=0,value=0,sz=0,info=0,other=0,shndx=0),**attrs))
	@staticmethod
	def parse_val(val):
		if type(val) in (int,long): return dict(value=val)
		elif type(val) in (tuple,list):
			ret=dict(value=val[0],sz=val[1])
			if len(val)>2:
				info=val[2].split()
				ret['info']=Elf32_SymInfo(0)
				ret['info'].binding=Elf32StBind(info[0])
				ret['info'].type=Elf32StType(info[1])
			return ret
		elif type(val)==dict: return val

class Elf32_Symtab(ArrayAttr):
	dtype=Elf32_Sym
	__slots__=["strtab","_names","_addrs","_last_fidx","_last_addidx"]
	def get__names(self): return {}
	def get__last_fidx(self): return 0
	def get__addrs(self): return []
	def get__last_addidx(self): return 0
	def resolve_addr(self,addr):
		for start,end,idx in self._addrs:
			if start<=addr and end>=addr: return self[idx]
		idx=self._last_addidx
		esize=get_cls_size(self.dtype)
		value_off=self.dtype._fields_.offsets["value"]
		fmt=struct.Struct("II")
		while True:
			if self._data_size<(idx*esize):
				self._last_addidx=idx
				raise ValueError,"No symbol for address %x"%(addr)
			offs=self._data_offset+idx*esize+value_off
			start,size=fmt.unpack_from(self._data,offs)
			end=start+size
			self._addrs.append((start,end,idx))
			if start<=addr and end>=addr:
				self._last_addidx=idx
				return self[idx]
			idx+=1
	def resolve_name(self,name):
		if name not in self._names: 
			while True:
				if self._last_fidx>=len(self.dlist): raise ValueError,"Have no %s symbol"%(name)
				curname=self.strtab.str_at(self[self._last_fidx].name)
				self._names[curname]=self[self._last_fidx]
				if curname==name: break
				self._last_fidx+=1
		return self._names[name]
	def add(self,symbols,textndx):
		for k,v in symbols.iteritems():
			self.append(Elf32_Sym.new(name=self.strtab.add(k),shndx=textndx,**Elf32_Sym.parse_val(v)))

class ELF32Header(BasePacketClass):
	_fields_=AttrList(('etype',Enum.mk("NONE REL EXEC DYN CORE",Short,"EType",LOPROC=0xff00,HIPROC=0xffff)),
		('machine',Enum.mk("NONE M32 SPARC 386 68K 88K 860 MIPS",Short,"EMachine",MIPS_RS4=10)),
		('version',Int,1),('entry',Int),('phoff',Int),('shoff',Int),('flags',Int),('ehsize',Short),('phentsize',Short),('phnum',Short),('shentsize',Short),('shnum',Short),('shstrndx',Short))
	__slots__=_fields_.keys()

class StringZTable(StringSZ):
	def str_at(self,offset):
		try: data=self._data
		except AttributeError:
			data=str(self)
			dofs=0
		else: dofs=self._data_offset
		return data[dofs+offset:data.index("\x00",dofs+offset)]
	def index(self,str): return self.value.index("%s\x00"%str)
	@classmethod
	def new(cls,strlist=[]):
		value=''.join(['%s\x00'%x for x in [""]+strlist])
		return cls(value=value,size=len(value))
	def add(self,data):
		idx=len(self.value)
		self.value="%s%s\x00"%(self.value,data)
		self.size=len(self.value)
		return idx

class ELF(BasePacketClass):
	def choose_header(self,data,offset=0,size=None):
		if self.eclass==1: return ELF32Header
		else: return StringSZ
	def get_strtab(self,sect=None):
		if sect is None: sect=self.sects[int(self.header.shstrndx)]
		return StringZTable(self.dstr,int(sect.fileoff)-self.dofs,int(sect.shsize))
	def get_sectndx(self,shname=None,shtype=None):
		if shname is not None: cond=lambda x: self.strtab.str_at(x.name)==shname
		elif shtype is not None: cond=lambda x: x.type==SHType(shtype)
		idx=0
		for sect in self.sects:
			if cond(sect): return idx
			idx=idx+1
		raise ValueError,"No section having shname=%r shtype=%r"%(shname,shtype)
	def get_sects_by_name(self,name):
		return filter(lambda x: self.strtab.str_at(x.name)==name,self.sects)
	def get_symtab(self):
		symtab=self.sects[self.get_sectndx(shtype="SYMTAB")]
		return Elf32_Symtab(self.dstr,int(symtab.fileoff)-self.dofs,int(symtab.shsize),strtab=self.get_strtab(self.sects[int(symtab.link)]))
	def get_dofs(self): return self._offsetof("data")
	def get_dstr(self): return str(self.data)
	def add_data(self,newdata,offset=-1):
		if offset==-1: offset=len(self.data)
		else: offset=offset-self.dofs
		data=str(self.data)
		self.data="%s%s%s"%(data[:offset],newdata,data[offset+len(newdata):])
		return offset+self.dofs
	def get_pheaders(self):
		return ArrayAttr._c(dtype=PHeader,count=self.header.phnum)(self.dstr,int(self.header.phoff)-self.dofs)
	def get_sects(self):
		return ArrayAttr._c(dtype=Elf32_Shdr,count=self.header.shnum)(self.dstr,int(self.header.shoff)-self.dofs)
	_fields_=AttrList('\x7fELF',('eclass',Enum.mk('? 32bit')),('dataenc',Byte,1),('version',Byte,1),('osabi',Byte,0),('abiver',Byte,0),('pad',StringSZ._c(size=7),'\x00'*7),('header',choose_header),('data',StringSZ))
	__slots__=_fields_.keys()+['pheaders','sects',"strtab","dofs","dstr","symtab"]
	def vaddr2offset(self,addr):
		matches=filter(lambda phdr: phdr.vaddr<=addr and phdr.memsz>=(addr-phdr.vaddr),self.pheaders)
		if not matches: raise ValueError,"Address %x not mapped"%(addr)
		phdr=matches[-1]
		return phdr.offset+addr-phdr.vaddr
	def vaddr2data(self,addr,size):
		foff=self.vaddr2offset(addr)-self.dofs
		return self.dstr[foff:foff+size]
	def offset2vaddr(self,offset):
		matches=filter(lambda phdr: phdr.offset<=offset and phdr.filesz>=(offset-phdr.offset),self.pheaders)
		if not matches: raise ValueError,"Offset %x not mapped"%(offset)
		phdr=matches[-1]
		return phdr.vaddr+offset-phdr.offset
	def sym2data(self,sym): return self.vaddr2data(sym.value,sym.sz)
	def add_symbols(self,symbols):
		try: symtab=self.symtab
		except ValueError:
			symtab=Elf32_Symtab([Elf32_Sym.new()],strtab=StringZTable.new())
		else: raise ValueError,"this program already has symtab"
		textndx=self.get_sectndx(shname=".text")
		shstrtab=self.strtab
		symstridx=shstrtab.add(".symtab")
		strtabidx=shstrtab.add(".strtab")
		symtab.add(symbols,textndx)
		strtab_ofs=self.add_data(symtab.strtab)
		symtab_ofs=self.add_data(symtab)

		self.sects[int(self.header.shstrndx)].fileoff=self.add_data(shstrtab)
		strtab_ndx=self.sects.append(Elf32_Shdr.new_strtab(name=symstridx,fileoff=strtab_ofs,shsize=len(symtab.strtab)))
		symtab_ndx=self.sects.append(Elf32_Shdr.new_symtab(name=strtabidx,fileoff=symtab_ofs,shsize=len(symtab),link=strtab_ndx))
		self.header.shoff=self.add_data(self.sects)
		self.header.shnum=len(self.sects.dlist)
	def only_symelf(self,symbols):
		ret=ELF(eclass="32bit",header=ELF32Header(etype="EXEC",machine="386",entry=self.header.entry,phoff=0x34,shoff=0,flags=0,ehsize=0x34,phentsize=0x20,phnum=0,shentsize=0x28,shnum=4,shstrndx=1),data='')
		strtab=StringZTable.new([".text",".strtab",".symtab",".shstrtab"])
		symtab=Elf32_Symtab([Elf32_Sym.new()],strtab=strtab)
		symtab.add(symbols,3)
		sects=ArrayAttr._c(dtype=Elf32_Shdr)([
			Elf32_Shdr.new(),
			Elf32_Shdr.new_strtab(fileoff=ret.add_data(strtab),name=strtab.index(".strtab"),shsize=len(strtab)),
			Elf32_Shdr.new_symtab(fileoff=ret.add_data(symtab),name=strtab.index(".symtab"),shsize=len(symtab),link=1),
			Elf32_Shdr.new_text(fileoff=0,addr=self.header.entry,name=strtab.index(".text"),shsize=self.get_sects_by_name(".text")[0].shsize),
			])
		ret.header.shoff=ret.add_data(sects)
		return ret

def mksymonlyelf(symbols={}):
	entry=0x8048000
	ret=ELF(eclass="32bit",header=ELF32Header(etype="EXEC",machine="386",entry=entry,phoff=0,shoff=0,flags=0,ehsize=0x34,phentsize=0x20,phnum=0,shentsize=0x28,shnum=0,shstrndx=0),data='')
	strtab=StringZTable.new([".text",".strtab",".symtab"]+symbols.keys())
	text_idx=3
	symtab=Elf32_Symtab([Elf32_Sym.new()]+[Elf32_Sym.new(shndx=3,name=strtab.index(k),**Elf32_Sym.parse_val(v)) for k,v in symbols.iteritems()],strtab=strtab)
	text=""
	sects=ArrayAttr._c(dtype=Elf32_Shdr)([
		Elf32_Shdr.new(),
		Elf32_Shdr.new_strtab(fileoff=ret.add_data(strtab),name=strtab.index(".strtab"),shsize=len(strtab)),
		Elf32_Shdr.new_symtab(fileoff=ret.add_data(symtab),name=strtab.index(".symtab"),shsize=len(symtab),link=1),
		Elf32_Shdr.new_text(fileoff=0,addr=0x08049b80,name=strtab.index(".text"),shsize=74780),
		])
	ret.header.shstrndx=1
	ret.header.shoff=ret.add_data(sects)
	ret.header.shnum=sects.count
	return ret

if __name__=='__main__':
	import sys,user
	from pprint import pprint
	elf=ELF(open(sys.argv[1]).read())
	print repr(elf)
