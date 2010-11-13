#!/usr/bin/python

import struct
import sys

max_uint=(sys.maxint<<1)+1

version=(0,2,0,20091116)

class DataMismatchError(Exception): pass

def djoin(*dicts):
	ret={}
	for d in dicts: ret.update(d)
	return ret

def hashx(obj): return hash(obj)&max_uint
#def clsname(obj): return '%s.%s'%(obj.__class__.__module__,obj.__class__.__name__)
def clsname(obj): return obj.__class__.__name__

def set_obj_attrtuple(obj,attrs,args):
	for idx,val in enumerate(args):
		try: setattr(obj,attrs[idx],val)
		except IndexError:
			raise ValueError,"%s does not have many args"%(clsname(obj))

def get_cls_size(cls):
	try: size=cls.size
	except AttributeError:
		try: size=cls._fields_.size
		except AttributeError: size=None
	if type(size) not in (int,long): size=None
	return size

_debug=False

class DynamicAttrClass(object):
	"""
	Used to create dynamically changing attribute objects
	If attribute <name> is not set for object, get_<name> will be called to get
	the value, and return value will be set as attribute.
	If set_<name> exists, it will be called when setting <name> attribute.

	_defaults define default values if name nor getter is found

	Subclass can define _tuple_attrs to define default attributes to be set via
	tuple during init.

	Has _c function to create sub-classes from class. _c takes keyword
	arguments to be set as attributes in the generated class definition.
	"""
	__slots__=['_tuple_attrs','_init_args']
	_defaults={}
	def __init__(self,*defarg,**args):
		"""
		All keyword arguments will be assigned to object attributes.
		Other arguments will be passed to _init_tuple function.
		"""
		self._init_args=args
		for k,v in args.iteritems(): setattr(self,k,v)
		self._init_args={}
		if defarg: self._init_tuple(*defarg)
	def __getattr__(self,key):
		if _debug: print "__getattr__(%r)"%(key)
		if not key.startswith('get_'):
			if key in self._init_args:
				setattr(self,key,self._init_args.pop(key))
				return getattr(self,key)
			try: getter=getattr(self,'get_%s'%(key))
			except AttributeError,e:
				if key!='_defaults' and key in self._defaults: return self._defaults[key]
			else:
				val=getter()
				setattr(self,key,val)
				try: val=object.__getattribute__(self,key)
				except AttributeError: pass
				if _debug: print "%s.__getattr__(%s)=%r"%(clsname(self),key,val)
				return val
		raise AttributeError,"%s has no %r attribute"%(clsname(self),key)
	def __setattr__(self,key,val):
		if not (key.startswith('_') or key.startswith('set_')):
			try: setter=getattr(self,'set_%s'%(key))
			except AttributeError:	object.__setattr__(self,key,val)
			else: setter(val)
		else: object.__setattr__(self,key,val)
	@classmethod
	def _c(cls,**attr):
		"""Make a subclass of this class, setting additional attributes"""
		return type('%s_g'%(cls.__name__),(cls,),dict(__slots__=cls.__slots__[:]+attr.keys(),**attr))
	def _init_tuple(self,*args):
		set_obj_attrtuple(self,self._tuple_attrs,args)

class Attr(object):
	__slots__=['name','index','default','atype','offset']
	def __init__(self,name,atype):
		self.name=name
		self.atype=atype

class AttrList(object):
	"""
	Used to generate list of subobject names, types and default values for
	BasePacketClass-based classes.
	Tries to pre-calculate offsets if initialized subobject types have size
	attribute.
	"""
	__slots__=['types','index','flow','defaults','offsets','constants','size','names','attrs','name_index']
	def __init__(self,*flow):
		"""
		Arguments will be parsed as list of: constant string or tuple
		containing (name,type,default) values. default is optional.
		"""
		self.index={}
		self.types={}
		self.defaults={}
		self.offsets={}
		self.constants=[]
		self.attrs=[]
		self.names=[]
		self.name_index={}
		self.flow=flow
		offset=0
		for idx,adef in enumerate(self.flow):
			if type(adef)==str:
				if offset is not None:
					self.constants.append((offset,adef,idx))
					offset+=len(adef)
			elif type(adef)==tuple:
				name,atype=adef[:2]
				attr=Attr(name,atype)
				self.name_index[name]=len(self.names)
				self.names.append(name)
				self.attrs.append(attr)
				self.index[name]=idx
				self.types[name]=atype
				if offset is not None:
					self.offsets[name]=offset
					try: asize=atype.size
					except AttributeError: offset=None
					else:
						if type(asize) in (int,long): offset+=asize
						else: offset=None
				if len(adef)>2: self.defaults[name]=adef[2]
			else: raise ValueError,"Unknown attr type in flow: %r, need str or tuple"%(type(adef))
		if offset is not None: self.size=offset
	def is_last(self,name): return len(self.flow)==self.index[name]+1
	def keys(self): return self.names
	def __contains__(self,key): return key in self.index
	def validate(self,data,data_offset=0):
		for offset,const,idx in self.constants:
			datapart=data[data_offset+offset:data_offset+offset+len(const)]
			if not datapart==const:
				raise DataMismatchError,"Magic mismatch %r != %r"%(datapart,const)
	def dup(self,**replace):
		"""Make copy of attribute list, optionally replacing some elements with list of other definitions"""
		newflow=[]
		for attr in self.flow:
			if type(attr)==str: newflow.append(attr)
			else:
				newattrs=replace.get(attr[0],attr)
				if not type(newattrs)==list: newattrs=[newattrs]
				for newattr in newattrs: newflow.append(newattr)
		return self.__class__(*newflow)
	@classmethod
	def mk(cls,defstr,le=True,**dtypes):
		flow=[]
		for idx,tdef in enumerate(defstr.split()):
			if tdef.startswith("\""):
				flow.append(tdef[1:-1].decode("string_escape"))
				continue
			try: st=tdef.index(":")
			except ValueError: name="ukn%d"%(idx)
			else: name,tdef=tdef[:st],tdef[st+1:]

			try: st=tdef.index("=")
			except ValueError: defval=None
			else: tdef,defval=tdef[:st],eval(tdef[st+1:])

			try: st=tdef.index("{")
			except ValueError: params=None
			else:
				en=tdef.index('}',st)
				tdef,params=tdef[:st],tdef[st:en]
			if tdef in dtypes: dtype=dtypes[tdef]
			else: dtype=eval(tdef)
			if params is not None:
				dtype_params=eval("dict(%s)"%params)
				dtype=dtype._c(dtype_params)
			if defval is None: flow.append((name,dtype))
			else: flow.append((name,dtype,defval))
		return cls(*flow)


class BasePacketClass(DynamicAttrClass):
	"""
	Base class for creating objects which consist of multiple sub-objects.
	_fields_ value will hold (typically AttrList type) special list of possible
	subobject names, which will be also accessible as object's attributes.

	Initialization can be done either by specifying attributes as keyword
	arguments, or as specifying data to be processed as a first argument,
	optionally setting reading offset (default 0) as second and available data
	size as third argument.

	All the subobjects will be converted before setting to subtype of
	BaseAttrClass (default specified in _fields_) or use type-setter function
	defined also in _fields_.

	When getting subobjects from data, objects will be created when accessed,
	not before. Also, <name>_size attributes will be automatically accessed to
	determine subobject's size, if subobject's type does not have size
	attribute.
	In case of subobject's class being subclass of ArrayAttr, also lookup for
	<name>_count will be made to determine number of array items.

	_repr function can be overwritten to add info in __repr__
	"""
	__slots__=['_fields_','_data','_data_offset','_attr_offsets','_data_size']
	def _init_dup(self,data):
		for attr_name in self.keys():
			if attr_name not in self._init_args:
				attr_val=getattr(data,attr_name)
				if isinstance(attr_val,(BaseAttrClass,BasePacketClass)): attr_val=attr_val.__class__(attr_val)
				setattr(self,attr_name,attr_val)
	def _init_new(self,data): return self._init_tuple(data,0,len(data))
	def _init_parse(self,data,data_offset,data_size):
		self._fields_.validate(data,data_offset)
		self._data=data
		self._data_offset=data_offset
		if data_size is not None: self._data_size=data_size
	def _init_tuple(self,data,offset=None,data_size=None):
		if isinstance(data,BasePacketClass): return self._init_dup(data)
		if offset is None:
			if data_size is None: return self._init_new(data)
			else: offset=0
		self._init_parse(data,offset,data_size)
	def get__attr_offsets(self): return {}
	def keys(self): return self._fields_.keys()
	def __str__(self): return ''.join(map(lambda x: str(self[x]),xrange(len(self._fields_.flow))))
	def __choose_atype_list(self,atype):
		for test,res in atype:
			if self.satisfies(**test): return res
	def parse_attrval(self,key,data=None,attr_offset=None):
		if data is None: data=self._data
		if attr_offset is None: attr_offset=self._offsetof(key)
		parseargs=(data,attr_offset+self._data_offset)
		initkwargs={}
		if not key.endswith('_size'):
			try: size=int(getattr(self,'%s_size'%(key,)))
			except AttributeError:
				try: data_size=self._data_size
				except AttributeError: pass
				else:
					if self._fields_.is_last(key):
						parseargs+=(data_size-attr_offset,)
			else: parseargs+=(size,)
		atype=self._fields_.types[key]
		if type(atype)==list: atype=self.__choose_atype_list(atype)
		if not type(atype)==type and callable(atype): atype=atype(self,*parseargs)
		if issubclass(atype,ArrayAttr) and not key.endswith('_count'):
			try: count=int(getattr(self,'%s_count'%(key,)))
			except AttributeError: pass
			else: initkwargs['count']=count
		if len(parseargs)==2:
			try: size=atype.size
			except AttributeError: pass
			else:
				if type(size) in (int,long):
					parseargs+=(size,)
		return atype(*parseargs,**initkwargs)
	def __getitem__(self,key):
		if type(key) in (int,long):
			a=self._fields_.flow[key]
			if type(a)==str: return a
			else: return getattr(self,a[0])
		elif type(key) in (str,unicode): return getattr(self,key)
		else: raise ValueError,"Key have to be string or integer"	
	def __getattr__(self,key):
		if _debug:
			print "%s.__getattr__(%r)"%(clsname(self),key)
		if not key.startswith('_') and key in self._fields_:
			if key in self._init_args:
				setattr(self,key,self._init_args.pop(key))
				return getattr(self,key)
			if hasattr(self,'_data'):
				setattr(self,key,self.parse_attrval(key))
				return getattr(self,key)
			else:
				if key in self._fields_.defaults:
					setattr(self,key,self._fields_.defaults[key])
					return getattr(self,key)
				elif key.endswith('_size') and key[:-5] in self._fields_:
					setattr(self,key,len(getattr(self,key[:-5])))
					return getattr(self,key)
				elif key.endswith('_count'):
					orig=key[:-6]
					if orig in self._fields_:
						orig_type=self._fields_.types[orig]
						if type(orig_type)==type and issubclass(orig_type,ArrayAttr):
							try: count=getattr(self,orig).count
							except AttributeError: pass
							else:
								setattr(self,key,count)
								return getattr(self,key)
		return DynamicAttrClass.__getattr__(self,key)
	def _offsetof(self,name):
		if name not in self._attr_offsets:
			off=getattr(self,'%s_offset'%name,None)
			if off is not None: self._attr_offsets[name]=off
			elif name in self._fields_.offsets: self._attr_offsets[name]=self._fields_.offsets[name]
			else:
				previdx=self._fields_.index[name]-1
				prevsize=0
				while type(self._fields_.flow[previdx])==str:
					prevsize+=len(self._fields_.flow[previdx])
					previdx=previdx-1
				prevname=self._fields_.flow[previdx][0]
				self._attr_offsets[name]=prevsize+self._offsetof(prevname)+len(getattr(self,prevname))
		return self._attr_offsets[name]
	def __setattr__(self,key,val):
		if key in self._fields_:
			if not isinstance(val,(BaseAttrClass,BasePacketClass)):
				atype=self._fields_.types[key]
				if type(atype)==list: atype=self.__choose_atype_list(atype)
				if type(atype)!=type and callable(atype): atype=atype(self,val)
				if not isinstance(val,atype): val=atype(val)
		DynamicAttrClass.__setattr__(self,key,val)
	def __len__(self):
		try: return self.size
		except AttributeError: pass
		try: return self._fields_.size
		except AttributeError: pass
		try: return self._data_size
		except AttributeError: pass
		size=0
		for field in self._fields_.flow:
			if type(field)==str:
				size+=len(field)
				continue
			try: size+=field[1].size
			except (AttributeError,TypeError):
				size+=len(self[field[0]])
		if size is not None: return size
		return len(str(self))
	def _repr(self): return ''
	def __repr__(self): return '<%s@%x %s>'%(clsname(self),hashx(self),self._repr())
	def _selfcheck(self):
		s=str(self)
		return len(self)==len(s) and self._data[self._data_offset:self._data_offset+self._data_size]
	def __eq__(self,other):
		if type(other)==dict: return self.satisfies(**other)
		return str(self)==str(other)
	@classmethod
	def register_atype(cls,attrname,atype):
		"""Register a new attribute type for conditional (list) attribute types"""
		cls._fields_.types[attrname].insert(0,atype)
	def satisfies(self,**cond):
		"""
		Returns True if all conditions match or there are no conditions.
		Condition names are splitted using __ to specify recursive attribute values
		Final attribute is tested against equality with condition value

		ex: ethpkt.satisfies(data__dsap==0xaa)
		"""
		for k,test in cond.iteritems():
			tgt=self
			for attr in k.split("__"):
				try: tgt=getattr(tgt,attr)
				except AttributeError,e:
					return False
			if tgt==test: pass
			else:
				return False
		return True
	def as_structure(self):
		"""Best to be used with pprint"""
		ret=[]
		for name in self._fields_.keys():
			data=getattr(self,name)
			inf=(name,data.__class__.__name__,data._repr())
			try: data.as_structure
			except AttributeError: pass
			else:
				inf=inf+(data.as_structure(),)
			ret.append(inf)
		return ret
	def pprint(self,*args,**kwargs):
		import pprint
		pprint.pprint(self.as_structure(),*args,**kwargs)


class BaseAttrClass(DynamicAttrClass):
	"""
	Base class for primitive subobject types.
	Depending if data offset was passed on as second argument in
	initialization, it will be initialized either from type-specific data via
	_init_new or from data string via _init_parse
	Third option may be specified to set available data size
	"""
	__slots__=[]
	def _init_tuple(self,data,data_offset=None,data_size=None):
		if isinstance(data,BaseAttrClass): self._init_dup(data)
		elif data_offset is None: self._init_new(data)
		else: self._init_parse(data,data_offset,data_size)
	def _repr(self): return ''
	def __repr__(self): return '<%s@%x %s>'%(clsname(self),hashx(self),self._repr())
	def __eq__(self,other): return str(self)==str(other)
	def _init_dup(self,basepkt): raise NotImplementedError,"%s needs to implement _init_dup"%(clsname(self))

class IntVal(BaseAttrClass):
	"""
	Base class for integer values.
	Subclass must implement fmt attribute of struct.Struct type
	"""
	__slots__=['value','size','fmt']
	def _init_dup(self,pkt): self.value=int(pkt.value)
	def _init_new(self,data): self.value=data
	def _init_parse(self,data,data_offset,data_size):
		try: self.value=self.fmt.unpack_from(data,data_offset)[0]
		except struct.error,e:
			raise ValueError,("Error unpacking %s"%(clsname(self)),e)
	def __str__(self): return self.fmt.pack(self.value)
	def _repr(self): return "0x%x"%(self.value)
	def __len__(self): return self.size
	def __mul__(self,other): return type(other)(self.value*other)
	def __cmp__(self,other): return cmp(self.value,int(other))
	def __nonzero__(self): return self.value!=0
	def __add__(self,other): return type(other)(self.value+other)
	def __radd__(self,other): return type(other)(other+self.value)
	def __sub__(self,other): return type(other)(self.value-other)
	def __rsub__(self,other): return type(other)(other-self.value)
	def __lshift__(self,shift): return self.value<<shift
	def __rshift__(self,shift): return self.value>>shift
	def __or__(self,other): return type(other)(self.value|other)
	def __ror__(self,other): return type(other)(other|self.value)
	def __and__(self,other): return type(other)(self.value&other)
	def __rand__(self,other): return type(other)(other&self.value)
	def __xor__(self,other): return type(other)(self.value^other)
	def __rxor__(self,other): return type(other)(other^self.value)
	def __int__(self): return self.value
	def __ne__(self,other): return not self==other
	def __eq__(self,other):
		if type(other) in (int,long): return self.value==other
		elif isinstance(other,IntVal): return self.value==other.value
		else: return BaseAttrClass.__eq__(self,other)
	def get_size(self): return self.fmt.size
	@staticmethod
	def _inttype_attr(inttype):
		if inttype is None: return {}
		else: return {'fmt':inttype.fmt,'size':inttype.fmt.size}

class IntValSZ(IntVal):
	__slots__=['le']
	le=True
	def _init_parse(self,data,data_offset,data_size):
		if data_size is None: data_size=self.size
		mydata=data[data_offset:data_offset+data_size]
		if not self.le: mydata=reversed(mydata)
		self.value=sum([(ord(c)<<(idx<<3)) for idx,c in enumerate(mydata)])
	def __len__(self):
		try: return self.size
		except AttributeError: pass
		size=1
		val=self.value
		while val>>(8*size):
			size+=1
		return size
	def __str__(self):
		ret=[]
		for idx in range(len(self)):
			ret.append(chr((self.value>>(idx<<3))&0xff))
		if not self.le: ret=reversed(ret)
		return ''.join(ret)

class Flags(IntVal):
	"""
	Baseclass for creating named flag integer values.
	"""
	__slots__=['flags']
	@classmethod
	def mk(cls,flagstr,inttype=None,**otherflags):
		"""
		Creates subclass from flag string and optional integer type for fmt.
		flagstr contains flag bit names and will be split by mkflags. It may
		contain ? characters for unnamed bits.
		If no inttype is given, integer type will be choosen automatically to
		fit given number of flags.
		"""
		attr={'flags':dict(cls.mkflags(flagstr),**otherflags)}
		if inttype is None:
			minsize=((len(attr['flags'])-1)>>3)+1
			try: inttype=filter(lambda x: x.fmt.size>=minsize,[Byte,Short,Int,Quad])[0]
			except IndexError: pass
		attr.update(IntVal._inttype_attr(inttype))
		return cls._c(**attr)
	def _init_new(self,data):
		if type(data)==list:
			self.value=0
			for flag in data: self.value|=self.flags[flag]
		else: IntVal._init_new(self,data)
	@staticmethod
	def mkflags(flagstr):
		ret={}
		flags=flagstr.split()
		bit=0
		while flags:
			flag=flags.pop(0)
			if flag=='?': flag='bit%d'%(bit)
			ret[flag]=1<<bit
			bit+=1
		return ret
	def __contains__(self,key):
		"""Check if certain flag is existent in value"""
		if self.value&self.flags[key]: return True
		else: return False
	def _repr(self):
		flags=[]
		flagsval=0
		for flag,val in self.flags.iteritems():
			if flag in self:
				flagsval|=val
				flags.append(flag)
		flags.sort(key=lambda x: self.flags[x])
		left=self.value^flagsval
		if left!=0: flags.append("0x%x"%(left))
		if not flags: flags=['0']
		return '|'.join(flags)
	def __getattr__(self,key):
		if not key.startswith('_') and key in self.flags:
			if self.value&self.flags[key]: return True
			else: return False
		else: return IntVal.__getattr__(self,key)
	def __setattr__(self,key,val):
		if not key.startswith('_') and key in self.flags:
			if val: self.value|=self.flags[key]
			else: self.value&=~self.flags[key]
		else: return IntVal.__setattr__(self,key,val)

class Enum(IntVal):
	__slots__=['enum','enum_rev','name']
	fmt=struct.Struct('B')
	size=fmt.size
	def _init_new(self,data):
		if type(data) in (str,unicode): data=self.enum_rev[data]
		IntVal._init_new(self,data)
	@classmethod
	def mk(cls,enum,inttype=None,__name__=None,**names):
		enum,enum_rev=cls.mkenum2(enum,**names)
		ret=cls._c(enum=enum,enum_rev=enum_rev,**IntVal._inttype_attr(inttype))
		if __name__ is not None: ret.__name__=__name__
		return ret
	@classmethod
	def mkenum2(cls,enum={},**names):
		enum=cls.mkenum(enum,**names)
		enum_rev=dict([(y,x) for x,y in enum.iteritems()])
		return enum,enum_rev
	@classmethod
	def mkenum(cls,enum={},**names):
		if type(enum)==str: enum=enum.split()
		if type(enum)==list: enum=dict([(idx,val) for idx,val in enumerate(enum) if not val=='?'])
		else: enum=enum.copy()
		for k,v in names.iteritems(): enum[v]=k
		return enum
	def _repr(self): return self.name
	def get_enum_rev(self): return dict([(y,x) for x,y in self.enum.iteritems()])
	def get_name(self): return self.enum.get(self.value,'UKN 0x%x'%self.value)
	def __getattr__(self,key):
		if not (key.startswith('_') or key.startswith('set_') or key.startswith('get_')) and key!='enum_rev' and key in self.enum_rev:
			return self.enum_rev[key]
		return IntVal.__getattr__(self,key)

class Byte(IntVal):
	__slots__=[]
	fmt=struct.Struct('B')
	size=fmt.size

class Short(IntVal):
	__slots__=[]
	fmt=struct.Struct('<H')
	size=fmt.size

class ShortBE(IntVal):
	__slots__=[]
	fmt=struct.Struct('>H')
	size=fmt.size

class Int(IntVal):
	__slots__=[]
	fmt=struct.Struct('<I')
	size=fmt.size

class Quad(IntVal):
	__slots__=[]
	fmt=struct.Struct('<Q')
	size=fmt.size
	
class QuadBE(IntVal):
	__slots__=[]
	fmt=struct.Struct('>Q')
	size=fmt.size


class IntBE(IntVal):
	__slots__=[]
	fmt=struct.Struct('>I')
	size=fmt.size

class StringSZ(BaseAttrClass):
	__slots__=['value','size','pad']
	def _init_dup(self,pkt):
		if isinstance(pkt,StringSZ): self.value=pkt.value
		else: self.value=str(pkt)
	def _init_new(self,data):
		self.value=data
		try: self.size=len(data)
		except AttributeError: pass
	def _init_parse(self,data,data_offset,data_size):
		if data_size is None: data_size=self.size
		elif hasattr(self,'size') and data_size<self.size:
			raise DataMismatchError,"Not enough data to fill %d bytes"%(self.size)
		else:
			try: self.size=data_size
			except AttributeError: pass
		self.value=data[data_offset:data_offset+data_size]
	def __str__(self):
		try: return self.value.ljust(self.size,self.pad)
		except AttributeError: return self.value
	def _repr(self):
		if hasattr(self,'value'):
			try: return '%r +%d*%r'%(self.value,self.size-len(self.value),self.pad)
			except AttributeError: return repr(self.value)
		else: return '(none)'
	def __len__(self): return self.size
	def __eq__(self,other): return self.value==other

class WStringSZ(StringSZ):
	def _init_new(self,data):
		if not type(data)==unicode: data=unicode(data)
		self.value=data
		try: self.size=len(data)*2
		except AttributeError: pass
	def _init_parse(self,data,data_offset,data_size):
		if data_size is None: data_size=self.size
		else:
			try: self.size=data_size
			except AttributeError: pass
		self.value=data[data_offset:data_offset+data_size].decode('utf-16-le')
	def __str__(self): return self.value.encode('utf-16-le')

class StringZ(StringSZ):
	__slots__=[]
	def _init_new(self,data):
		self.value=data
		self.size=len(self.value)+1
	def _init_parse(self,data,data_offset,data_size):
		idx=data.index('\x00',data_offset)
		self.value=data[data_offset:idx]
		self.size=idx-data_offset+1
		if data_size is not None and self.size!=data_size:
			raise ValueError,"Specified data size %s does not match real size %s"(data_size,self.size)
	def __str__(self): return '%s\x00'%self.value

class WStringZ(StringSZ):
	__slots__=[]
	def _init_new(self,data):
		if not type(data)==unicode: data=unicode(data)
		self.value=data
		self.size=(len(self.value)+1)*2
	def _init_parse(self,data,data_offset,data_size):
		idx=data_offset
		while True:
			idx=data.index('\x00\x00',idx)
			if (idx-data_offset)%2: idx+=1
			else: break
		self.value=data[data_offset:idx].decode('utf-16-le')
		self.size=(idx-data_offset)+2
		if data_size is not None and self.size!=data_size:
			raise ValueError,"Specified data size %s does not match real size %s"(data_size,self.size)
	def __str__(self): return '%s\x00\x00'%self.value.encode('utf-16-le')

class ArrayAttr(BaseAttrClass):
	__slots__=['dtype','dlist','_dcache','end','count','_offsets','_data_size','_data','_data_offset','_dlist']
	def _init_dup(self,other):
		self.dlist=[]
		for v in other.dlist:
			if isinstance(v,(BaseAttrClass,BasePacketClass)): v=v.__class__(v)
			self.dlist.append(v)
		self.count=len(self.dlist)
	def _init_new(self,data):
		self.dlist=[]
		for val in data:
			atype=self.dtype
			if not isinstance(val,(BaseAttrClass,BasePacketClass)):
				if type(atype)!=type and callable(atype): atype=atype(self,val)
				if not isinstance(val,atype): val=atype(val)
			self.dlist.append(val)
		self.count=len(self.dlist)
	def _init_parse(self,data,offset,size):
		self._offsets={}
		self._data=data
		self._data_offset=offset
		if size is not None: self._data_size=size
		self._dcache={}
	def _offsetof(self,nr):
		if nr==0: return 0
		if nr not in self._offsets:
			dtype_size=get_cls_size(self.dtype)
			if dtype_size is not None: offset=dtype_size*nr
			else: offset=self._offsetof(nr-1)+self._sizeof(nr-1)
			self._offsets[nr]=offset
		return self._offsets[nr]
	def _sizeof(self,nr):
		size=get_cls_size(self.dtype)
		if size is None: size=len(self[nr])
		return size
	def __len__(self):
		try: count=len(self.dlist)
		except AttributeError: count=self.count
		return sum([self._sizeof(x) for x in range(count)])
	def get_dlist(self):
		try: return self._dlist
		except AttributeError: return [x for x in self]
	def set_dlist(self,dlist):
		object.__setattr__(self,'dlist',dlist)
		self._dlist=dlist
	def __iter__(self):
		try: dlist=self._dlist
		except AttributeError:
			dlist=[]
			try: count=self.count
			except AttributeError:
				try: end=self.end
				except AttributeError:
					try: data_size=self._data_size
					except AttributeError: 
						raise ValueError,"No criteria to determine end of the list"
					else:
						idx=0
						while data_size>0:
							data=self[idx]
							dlist.append(data)
							yield data
							data_size-=len(data)
							idx+=1
						if data_size<0:
							raise ValueError,"Data exceeds allowed size"
						self._dlist=dlist
				else:
					idx=0
					while True:
						data=self[idx]
						dlist.append(data)
						yield data
						if callable(end) and end(self,data): break
						elif data==end: break
						idx+=1
					self._dlist=dlist
			else: 
				for x in xrange(count): yield self[x]
		else:
			for elem in dlist: yield elem
	def __getitem__(self,nr):
		try: data=self._data
		except AttributeError: return self.dlist[nr]
		else:
			try: data_size=self._data_size
			except AttributeError:
				if nr>=self.count: raise IndexError,"Specified index is bigger than count"
				data_size=None
		if nr not in self._dcache:
			size=get_cls_size(self.dtype)
			data=self.dtype(data,self._data_offset+self._offsetof(nr),size)
			if data_size is not None and self._offsetof(nr)+len(data) > data_size:
				raise IndexError,"Specified index is out of data range"
			self._dcache[nr]=data
		return self._dcache[nr]
	def append(self,item):
		self.dlist.append(item)
		return len(self.dlist)-1
	def _repr(self):
		try: count=int(self.count)
		except AttributeError: count=""
		return '%s[%s]'%(self.dtype.__name__,count)
	def __str__(self):
		return ''.join([str(x) for x in self.dlist])
	def as_structure(self):
		ret=[]
		for item in self:
			try: s=item.as_structure
			except AttributeError: ret.append(item)
			else: ret.append(item.as_structure())
		return ret
