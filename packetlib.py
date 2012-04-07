#!/usr/bin/python

import struct
import sys
import traceback
from functools import wraps
from warnings import warn
from types import MemberDescriptorType
import os

max_uint=(sys.maxint<<1)+1

version=(0,2,0,20091116)

class DataMismatchError(Exception): pass
class _AttrErr(AttributeError): pass
class CyclicAttributeError(RuntimeError): pass
class AttributeGetterError(RuntimeError): pass

def djoin(*dicts):
	ret={}
	for d in dicts: ret.update(d)
	return ret

def hashx(obj): return id(obj)&max_uint
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

_debug="DEBUG_PACKETLIB" in os.environ

def prop_ref(obj, name):
	name_map=[obj]+name.split(".")
	def fget(self):
		return reduce(lambda x,y: getattr(x,y),name_map)
	def fset(self,val):
		tgt_obj=reduce(lambda x,y: getattr(x,y),name_map[:-1])
		return setattr(tgt_obj,name_map[-1],val)
	return property(fget,fset)

def set_get_attr(obj, name, val):
	if _debug:
		print "set_get %s.%s"%(obj.__class__.__name__,name)
		traceback.print_stack()
	setattr(obj, name, val)
	return getattr(obj, name, val)

def no_fail(f):
	"""Wrapper for functions which are not allowed to raise exceptions.
	Useful for functions whose AttributeError might get ignore otherwise.
	raises RuntimeError in case of any exception
	"""
	@wraps(f)
	def deco(*args,**kwargs):
		try: return f(*args,**kwargs)
		except Exception,e:
			raise RuntimeError("Unhandled exception",f.__name__,e),None,sys.exc_info()[2]
	return deco

class cached_property(object):
	__slots__=["fget","fset","__name__","cls","default"]
	__re_entrance={}
	def __init__(self, fget=None, fset=None, name=None,cls=None):
		if fget is not None:
			self.fget=fget
		if name is not None: self.__name__=name
		elif fget is not None: self.__name__=fget.__name__
		if cls is not None: self.cls=cls
		if fset is not None: self.fset=fset
	def copy(self):
		ret=self.__class__()
		for k in "fset","fget","__name__":
			try: v=getattr(self,k)
			except AttributeError: pass
			else: setattr(ret, k, v)
		return ret
	def __repr__(self): return "<%s %r>"%(self.__class__.__name__,getattr(self,"__name__","<noname>"))
	def _set_with_setter(self, instance, value, none_nosave=True):
		try: fset=self.fset
		except AttributeError: pass
		else:
			value_new=fset(instance, value)
			if value_new is not None: value=value_new
			elif none_nosave: return
		try: instance._property_cache[self.__name__]=value
		except AttributeError: instance._property_cache={self.__name__:value}
		return value
	def __get__(self, instance, owner):
		try:
			if instance is None: return self
			name=self.__name__
			try: return instance._property_cache[name]
			except AttributeError: instance._property_cache={}
			except KeyError: pass
			try: init_args=instance._init_args
			except AttributeError: pass
			else:
				try: val=init_args[name]
				except KeyError: pass
				else:
					return self._set_with_setter(instance, val, none_nosave=False)
			reent_id=(instance.__class__.__name__,name,id(instance))
			if reent_id in self.__re_entrance:
				raise CyclicAttributeError("Cyclic attribute detected",map(lambda x: "<{0}.{1} at {2:#x}>".format(*x[0]),sorted(self.__re_entrance.items(),key=lambda x: x[1])))
			self.__re_entrance[reent_id]=len(self.__re_entrance)
			try: fget=self.fget
			except AttributeError:
				try: val=self.default
				except AttributeError:
					raise _AttrErr(AttributeError("No default for property %s.%s"%(instance.__class__.__name__,name)),sys.exc_info()[2])
			else:
				try: val=fget(instance)
				except AttributeError,e: raise _AttrErr(e,sys.exc_info()[2])
			val=self._set_with_setter(instance, val, none_nosave=False)
			del self.__re_entrance[reent_id]
			return val
		except _AttrErr,e:
			raise e[0],None,e[1]
		except CyclicAttributeError:
			self.__re_entrance.clear()
			raise
		except Exception,e:
			if isinstance(e, AttributeError):
				e=AttributeGetterError("Error getting attribute",e)
			raise e,None,sys.exc_info()[2]
	@no_fail
	def __set__(self, instance, value):
		self._set_with_setter(instance, value, none_nosave=True)
	def __delete__(self, instance):
		try: del instance._property_cache[self.__name__]
		except (AttributeError,KeyError):
			raise AttributeError("%r object has no attribute %r"%(instance.__class__.__name__,self.__name__))
	def setter(self, fset):
		self.fset=fset
		return self
	def getter(self, fget):
		self.fget=fget
		return self

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
	class __metaclass__(type):
		def set_attr(self, cls, key, val, keytype=None):
			try: attr_v=getattr(cls, key)
			except AttributeError: attr_v=None
			if attr_v is None or isinstance(attr_v,MemberDescriptorType):
				attr_v=cached_property(name=key, cls=cls)
			else:
				if attr_v.cls is not cls:
					attr_v=attr_v.copy()
			if keytype=="set": attr_v.setter(val)
			elif keytype=="get": attr_v.getter(val)
			elif keytype=="default": attr_v.default=val
			else: raise RuntimeError("unknown key type",keytype)
			setattr(cls, key, attr_v)
		def __init__(self, cls_name, bases, cls_dict):
			for k,v in cls_dict.items():
				if k.startswith("set_") or k.startswith("get_"):
					self.set_attr(self, k[4:], v, k[:3])
			try: defaults=self._defaults
			except AttributeError: pass
			else:
				for k,v in defaults.iteritems():
					self.set_attr(self, k, v, "default")
			return type.__init__(self, cls_name, bases, cls_dict)
		def __new__(self, cls_name, bases, cls_dict):
			if "__slots__" in cls_dict: cls_dict["__slots__"].append("_property_cache")
			return type.__new__(self, cls_name, bases, cls_dict)
	def __sort_attr_arg_keys(self, key):
		try: desc=getattr(self.__class__, key)
		except AttributeError: return 0
		if isinstance(desc,cached_property): return 2
		else: return 1
	def __init__(self,*defarg,**args):
		"""
		All keyword arguments will be assigned to object attributes.
		Other arguments will be passed to _init_tuple function.
		"""
		self._init_args=args
		for k in sorted(args.keys(),key=self.__sort_attr_arg_keys):
			setattr(self,k,args[k])
		self._init_args={}
		if defarg: self._init_tuple(*defarg)
	@classmethod
	def _c(cls,**attr):
		"""Make a subclass of this class, setting additional attributes"""
		return type('%s_g'%(cls.__name__),(cls,),dict(__slots__=attr.keys(),**attr))
	def _init_tuple(self,*args):
		set_obj_attrtuple(self,self._tuple_attrs,args)

class Attr(cached_property):
	__slots__=['name','index','type','offset',"const"]
	def __init__(self,**attrs):
		for k,v in attrs.iteritems(): setattr(self,k,v)
	def copy(self):
		ret=super(Attr, self).copy()
		try: ret.name=self.name
		except AttributeError: ret.const=self.const
		else:
			ret.type=self.type
			try: ret.default=self.default
			except AttributeError: pass
		return ret
	def __repr__(self): return "<%s %r>"%(self.__class__.__name__,getattr(self,"name",None))
	def parse_value(self, instance):
		offset=self.get_offset(instance)
		parseargs=[instance._data,instance._data_offset+offset]
		try: sz=self.__len__(instance)
		except AttributeError:
			try: data_size=instance._data_size
			except AttributeError: pass
			else:
				if self.index==len(instance._fields_.flow)-1:
					parseargs.append(data_size-offset)
		else: parseargs.append(sz)
		atype=self.choose_type(instance,*parseargs)
		add_args={}
		if issubclass(atype,ArrayAttr):
			try: count=int(getattr(instance,"%s_count"%self.name))
			except AttributeError: pass
			else: add_args["count"]=count
		if len(parseargs)==2:
			sz=getattr(atype,"size",None)
			if isinstance(sz,(int,long)):
				parseargs.append(sz)
		return atype(*parseargs,**add_args)
	def get_offset(self,instance):
		try: return instance._attr_offsets[self.index]
		except KeyError: pass
		try: offset=self.offset
		except AttributeError:
			try: offset=int(getattr(instance,"%s_offset"%self.name))
			except AttributeError:
				prev_attr=instance._fields_[self.index-1]
				try: prev_size=prev_attr.__len__(instance)
				except AttributeError: prev_size=len(prev_attr.get_value(instance))
				offset=prev_attr.get_offset(instance)+prev_size
		instance._attr_offsets[self.index]=offset
		return offset
	def get_value(self, instance):
		try: name=self.name
		except AttributeError: return self.const
		try: return instance._field_cache[name]
		except AttributeError: instance._field_cache={}
		except KeyError: pass
		if hasattr(instance, "_data"):
			return set_get_attr(instance, name, self.parse_value(instance))
		try: return set_get_attr(instance, name, self.fget(instance))
		except AttributeError:
			if name.endswith("_size"):
				try: return set_get_attr(instance,name,len(getattr(instance,name[:-len("_size")])))
				except AttributeError: pass
			try: return set_get_attr(instance, name, self.default)
			except AttributeError:
				raise _AttrErr(AttributeError("No default value for field attr %s.%s"%(instance.__class__.__name__,name)),sys.exc_info()[2])
	def __get__(self, instance, owner):
		if instance is None: return self
		try: val=self.get_value(instance)
		except _AttrErr,e: raise e[0],None,e[1]
		except Exception,e:
			raise RuntimeError("Exception when getting attribute",e),None,sys.exc_info()[2]
		else: return val
	def choose_type(self, instance, *type_args):
		atype=self.type
		if isinstance(atype,list):
			for test,res in atype:
				if instance.satisfies(**test):
					atype_new=res
					break
			atype=atype_new
		if not isinstance(atype,type) and callable(atype):
			atype=atype(instance,*type_args)
		return atype
	def __len__(self, instance=None):
		if not hasattr(self, "name"): return len(self.const)
		try: sz=self.type.size
		except AttributeError: sz=None
		if isinstance(sz,(int,long)): return sz
		if instance is not None:
			return int(getattr(instance,"%s_size"%self.name))
		raise AttributeError("No size for field %r"%(self.name))
	@no_fail
	def __set__(self, instance, value):
		try: fset=self.fset
		except AttributeError: pass
		else:
			value=fset(instance, value)
			if value is None:
				warn(DeprecationWarning("field setter %s.set_%s should return new value"%(instance.__class__.__name__,self.name)))
		if not isinstance(value,(BaseAttrClass,BasePacketClass)):
			atype=self.choose_type(instance, value)
			if not isinstance(value,atype):
				value=atype(value)
		try: cache=instance._field_cache
		except AttributeError: cache=instance._field_cache={}
		cache[self.name]=value
	def __delete__(self, instance):
		try: del instance._field_cache[self.name]
		except (AttributeError,KeyError):
			raise AttributeError("field %s.%s not set",instance.__class__.__name__, self.name)

class _AttrListDefaultsReplacement(object):
	__slots__=["attrlist"]
	def __init__(self, attrlist):
		self.attrlist=attrlist
	def __getitem__(self,key):
		return self.attrlist[key].default	

class AttrList(object):
	"""
	Used to generate list of subobject names, types and default values for
	BasePacketClass-based classes.
	Tries to pre-calculate offsets if initialized subobject types have size
	attribute.
	"""
	__slots__=['flow','size','names']
	def __init__(self,*flow):
		"""
		Arguments will be parsed as list of: constant string or tuple
		containing (name,type,default) values. default is optional.
		"""
		self.names={}
		self.flow=[]
		offset=0
		for idx,adef in enumerate(flow):
			if isinstance(adef,str):
				attr=Attr(const=adef,index=idx)
				self.flow.append(attr)
				if offset is not None:
					attr.offset=offset
					offset+=len(adef)
			elif isinstance(adef,tuple):
				name,atype=adef[:2]
				attr=Attr(name=name,type=atype,index=idx)
				self.names[name]=attr
				self.flow.append(attr)
				if len(adef)>2: attr.default=adef[2]
				if offset is not None:
					attr.offset=offset
					try: offset+=len(attr)
					except AttributeError: offset=None
			else: raise ValueError,"Unknown attr type in flow: %r, need str or tuple"%(type(adef))
		if offset is not None: self.size=offset
	def keys(self): return [a.name for a in self if hasattr(a,"name")]
	def __getitem__(self, key):
		if isinstance(key,(int,long)):
			return self.flow[key]
		else: return self.names[key]
	def __contains__(self,key): return key in self.names
	def validate(self,data,data_offset=0):
		for attr in self:
			if hasattr(attr,"name"): continue
			try: offset=attr.offset
			except AttributeError: continue
			datapart=data[data_offset+offset:data_offset+offset+len(attr)]
			if not attr.const==datapart:
				raise DataMismatchError("Magic mismatch %r != %r"%(datapart,attr))
	def dup(self,**replace):
		"""Make copy of attribute list, optionally replacing some elements with list of other definitions"""
		newflow=[]
		for attr in self.flow:
			if type(attr)==str: newflow.append(attr)
			else:
				try: repl=replace[attr.name]
				except KeyError:
					try: default=attr.default
					except AttributeError: newflow.append((attr.name,attr.type))
					else: newflow.append((attr.name,attr.type,default))
				else:
					if isinstance(repl,list): newflow.extend(repl)
					else: newflow.append(repl)
		return self.__class__(*newflow)
	@property
	def defaults(self): return _AttrListDefaultsReplacement(self)
	def __iter__(self):
		for v in self.flow: yield v
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
	class __metaclass__(DynamicAttrClass.__metaclass__):
		def __init__(self, cls_name, bases, cls_dict):
			try: fields=cls_dict["_fields_"]
			except KeyError: pass
			else:
				for attr in fields:
					attr.cls=self
					try: name=attr.name
					except AttributeError: pass
					else:
						setattr(self,name,attr)
						if hasattr(self, "get_%s"%name): attr.fget=getattr(self, "get_%s"%name)
						if hasattr(self, "set_%s"%name): attr.fset=getattr(self, "set_%s"%name)
			return DynamicAttrClass.__metaclass__.__init__(self, cls_name, bases, cls_dict)
		def __new__(self, cls_name, bases, cls_dict):
			if "__slots__" in cls_dict: cls_dict["__slots__"].append("_field_cache")
			return DynamicAttrClass.__metaclass__.__new__(self, cls_name, bases, cls_dict)

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
	def __str__(self):
		try: return ''.join(map(lambda x: str(x.get_value(self)),self._fields_))
		except _AttrErr,e: raise e[0],None,e[1]
	def __getitem__(self,key):
		if type(key) in (int,long):
			a=self._fields_.flow[key]
			if type(a)==str: return a
			else: return getattr(self,a.name)
		elif type(key) in (str,unicode): return getattr(self,key)
		else: raise ValueError,"Key have to be string or integer"
	def _offsetof(self, name):
		return self._fields_[name].get_offset(self)
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
			try: size+=len(field)
			except (AttributeError,TypeError):
				size+=len(self[field.name])
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
				except AttributeError:
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

class FreeSizeFormat(DynamicAttrClass):
	__slots__=["le","size"]
	_tuple_attrs=("size","le")
	def __repr__(self): return "<%s.%s %d byte %s at 0x%x>"%(self.__class__.__module__,
		self.__class__.__name__,self.size,"LE" if self.le else "BE",id(self))
	def unpack_from(self, data, offset=0):
		data=data[offset:offset+self.size]
		if len(data)<self.size: raise ValueError("Not enough data to unpack",data,self.size)
		if not self.le: data=reversed(data)
		return (sum([(ord(c)<<(idx<<3)) for idx,c in enumerate(data)]),)
	def unpack(self, data): return self.unpack_from(data, 0)
	def pack(self, value):
		if value>=(1<<(self.size<<3)):
			raise ValueError("Too large value for size",self.size, value)
		ret=[chr((value>>(idx<<3))&0xff) for idx in range(self.size)]
		if not self.le: ret=reversed(ret)
		return "".join(ret)

class IntValSZ(IntVal):
	__slots__=['le']
	le=True
	def get_size(self):
		val=self.value
		sz=0
		while True:
			sz+=1
			val=val>>8
			if not val: break
		return sz
	def get_fmt(self):
		return FreeSizeFormat._c(size=property(lambda s: self.size),le=property(lambda s: self.le))()
	def _init_parse(self,data,data_offset,data_size):
		if data_size is None: data_size=self.size
		else: self.size=data_size
		return super(IntValSZ, self)._init_parse(data, data_offset, data_size)

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
	__slots__=['enum','enum_rev']
	fmt=struct.Struct('B')
	size=fmt.size
	def _init_new(self,data):
		if type(data) in (str,unicode): data=self.enum_rev[data]
		IntVal._init_new(self,data)
	@classmethod
	def mk(cls,enum,inttype=None,__name=None,**names):
		enum,enum_rev=cls.mkenum2(enum,**names)
		ret=cls._c(enum=enum,enum_rev=enum_rev,**IntVal._inttype_attr(inttype))
		if __name is not None: ret.__name__=__name
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

class StringTOK(StringSZ):
	__slots__=["token"]
	def _init_new(self,data):
		self.value=data
		self.size=len(self.value)+len(self.token)
	def _init_parse(self,data,data_offset,data_size):
		idx=data.index(self.token,data_offset)
		self.value=data[data_offset:idx]
		self.size=idx-data_offset+len(self.token)
		if data_size is not None and self.size!=data_size:
			raise ValueError,"Specified data size %s does not match real size %s"(data_size,self.size)
	def __str__(self): return '%s%s'%(self.value,self.token)

class StringZ(StringTOK):
	__slots__=[]
	token="\x00"

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
		self._dlist=dlist
		return dlist
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
			else: ret.append(s())
		return ret
