#!/usr/bin/python

import os,sys,imp
import gtk
import packetlib

class GtkBuilderUI(object):
	def __init__(self,filename,cbobj=None):
		self._filename=filename
		self._ui=gtk.Builder()
		self._ui.add_from_file(filename)
		if cbobj!=None: self._ui.connect_signals(cbobj)
	def __getattr__(self,key):
		if key[0]=='_': raise AttributeError,key
		val=self._ui.get_object(key)
		if val!=None:
			setattr(self,key,val)
			return val
		raise AttributeError,"No '"+key+"' attribute in "+str(self._filename)

def _fmon(func):
	print >>sys.stderr,"monitor %r"%(func.func_name)
	def f(*args,**kwargs):
		print >>sys.stderr,"call(%s.%s): %r,%r"%(type(args[0]).__name__,func.func_name,args[1:],kwargs),
		sys.stderr.flush()
		ret=func(*args,**kwargs)
		print >>sys.stderr,"ret(%s): %r"%(func.func_name,ret)
		return ret
	return f

class DummyPacket(packetlib.BasePacketClass):
	_fields_=packetlib.AttrList(("data",packetlib.StringSZ))

class PacketTreeModel(gtk.GenericTreeModel):
	packet=None
	def on_get_flags(self): return 0
	def on_get_n_columns(self): return 3
	def on_get_column_type(self, index): return str
	#@_fmon
	def on_get_iter(self, path):
		if self.packet is None: return None
		if path[0]==0:
			ret=()
			for p in path[1:]:
				pkt=self._ref_to_obj(ret)
				if isinstance(pkt,packetlib.ArrayAttr): ret=ret+(p,)
				else: ret=ret+(pkt._fields_.names[p],)
			return ret
		raise NotImplementedError,"on_get_iter not implemented for path=%r"%(path,)
	def on_get_path(self, rowref):
		ret=(0,)
		obj=self.packet
		for idx,name in enumerate(rowref):
			if type(name)==int: n=name
			else: n=obj._fields_.name_index[name]
			ret=ret+(n,)
			if idx<len(rowref)-1: obj=getattr(obj,name)
		print 'on_get_path: %r -> %r (%r)'%(rowref,ret,obj)
		return ret
	#@_fmon
	def on_get_value(self, rowref, column):
		if self.packet is None: return None
		if column is 0:
			if rowref==(): return self.packet.__class__.__name__
			return rowref[-1]
		elif column is 1:
			obj=self._ref_to_obj(rowref)
			r=obj._repr()
			if isinstance(obj,packetlib.StringSZ) and len(r)>32: r='%s..'%(r[:32])
			return r
		elif column is 2:
			cls=type(self._ref_to_obj(rowref))
			return '%s.%s'%(cls.__module__,cls.__name__)
		raise NotImplementedError,"on_get_value not implemented for rowref=%r, column=%r"%(rowref,column)
	#@_fmon
	def on_iter_next(self, rowref):
		if rowref==(): return None
		obj,name=self._ref_to_obj(rowref[:-1]),rowref[-1]
		if type(name)==int:
			if len(obj.dlist)>name+1: return rowref[:-1]+(name+1,)
			else: return None
		idx=obj._fields_.name_index[name]
		try: return rowref[:-1]+(obj._fields_.names[idx+1],)
		except IndexError: return None
		raise NotImplementedError,"on_iter_next not implemented for rowref=%r"%(rowref,)
	#@_fmon
	def on_iter_children(self, parent):
		obj=self._ref_to_obj(parent)
		if isinstance(obj,packetlib.ArrayAttr):
			return parent+(0,)
		else: return parent+(obj._fields_.names[0],)
	#@_fmon
	def on_iter_has_child(self, rowref):
		obj=self._ref_to_obj(rowref)
		if obj is None: return False
		elif isinstance(obj,packetlib.BasePacketClass): return True
		elif isinstance(obj,packetlib.ArrayAttr): return len(obj.dlist)>0
		else: return False
	#@_fmon
	def on_iter_n_children(self, rowref):
		if rowref is None:
			if self.packetlib is None: return 0
			else: return 1
		obj=self._ref_to_obj(rowref)
		if isinstance(obj,packetlib.ArrayAttr): return len(obj.dlist)
		return len(obj._fields_.names)
		raise NotImplementedError,"on_iter_n_children not implemented for rowref=%r"%(rowref,)
	#@_fmon
	def on_iter_nth_child(self, parent, n):
		if parent is None and n==0 and self.packet is not None: return ()
		obj=self._ref_to_obj(parent)
		if isinstance(obj,packetlib.ArrayAttr) and n<len(obj.dlist):
			return parent+(n,)
		try: return parent+(obj._fields_.names[n],)
		except IndexError: pass
		raise NotImplementedError,"on_iter_nth_child not implemented for parent=%r, n=%r"%(parent,n)
	#@_fmon
	def on_iter_parent(self, child):
		return child[:-1]
	def _ref_to_obj(self,ref):
		ret=self.packet
		for attr in ref:
			if type(attr)==int: ret=ret[attr]
			else:
				try: ret=getattr(ret,attr)
				except AttributeError:
					print "Error getting %r"%(ref,)
					raise
		return ret
	def set_packet(self,packet):
		if self.packet is None:
			if packet is None: change=0
			else: change=1
		else:
			if packet is None: change=2
			else: change=3
		self.packet=packet
		self.invalidate_iters()
		topiter=self.get_iter_root()
		if change is 1: self.row_inserted((0,),topiter)
		elif change is 2: self.row_deleted((0,))
		elif change is 3: self.row_changed((0,),topiter)
		if change in (1,3):
			self.row_has_child_toggled((0,),topiter)

class GtkUI(object):
	def __getattr__(self,key):
		if not key.startswith('_'): print >>sys.stderr,"No attribute: %s"%(key)
		raise AttributeError,"No %r attribute"%(key)
	def __init__(self):
		self.ui=GtkBuilderUI(os.path.join(os.path.dirname(__file__),'gui.ui'),self)
		self.pktstore=PacketTreeModel()
		self.ui.pktree.set_model(self.pktstore)
		self.ui.pktree.insert_column_with_attributes(-1,'Pkt',gtk.CellRendererText(),text=0)
		self.ui.pktree.insert_column_with_attributes(-1,'Value',gtk.CellRendererText(),text=1)
		self.ui.pktree.insert_column_with_attributes(-1,'Type',gtk.CellRendererText(),text=2)
		self.reset()
		self.module_load_count=0
		self.imp_suffixes=dict([(x[0],x) for x in imp.get_suffixes()])
	def reset(self):
		self.pclass=DummyPacket
		self.pmod=None
		self.data=""
		self.data_offset=0
		self.reload()
	def reload(self):
		self.ui.offsetentry.set_text(str(self.data_offset))
		if self.pclass is not None and self.data is not None:
			self.pktstore.set_packet(self.pclass(self.data,self.data_offset))
		else:
			self.pktstore.set_packet(None)
	def run(self):
		self.ui.offsetentry.set_text(str(self.data_offset))
		if self.pclass is not None and self.pmod is not None:
			self.ui.pname.child.set_text(self.pclass.__name__)
		gtk.main()
	def on_new(self,*args): self.reset()
	def on_mainwin_delete(self,*args): gtk.main_quit()
	def on_menu_quit_activate(self,*args): gtk.main_quit()
	def on_offsetentry_activate(self,entry):
		self.data_offset=int(entry.get_text())
		self.reload()
	def on_dfchooser_file_set(self,chooser):
		fname=chooser.get_filename()
		if fname is not None: self.set_file(fname)
	def set_file(self,fname):
		self.data=open(fname).read()
		self.ui.dfchooser.set_filename(os.path.abspath(fname))
		self.reload()
	def set_pclass(self,clsname):
		self.pclass=getattr(self.pmod,clsname)
		self.reload()
	def on_pname(self,entry): self.set_pclass(entry.child.get_text())
	def load_pfile(self,fname):
		self.pmod=imp.load_module("pmodule_%d"%self.module_load_count,open(fname),fname,self.imp_suffixes[fname[fname.rindex("."):]])
		self.module_load_count+=1
		self.ui.pname_store.clear()
		for name in dir(self.pmod):
			obj=getattr(self.pmod,name)
			if type(obj)==type(packetlib.BasePacketClass) and issubclass(obj, packetlib.BasePacketClass) and obj is not packetlib.BasePacketClass:
				self.ui.pname_store.append((obj.__name__,))
	def on_pfile_file_set(self,fchooser): self.load_pfile(fchooser.get_filename())

if __name__=='__main__':
	ui=GtkUI()
	if len(sys.argv)>1:
		pfile,pclass=sys.argv[1].split(":")
		ui.load_pfile(pfile)
		ui.set_pclass(pclass)
	if len(sys.argv)>2: ui.set_file(sys.argv[2])
	ui.run()
