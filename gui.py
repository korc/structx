#!/usr/bin/python

import os,sys,imp
import gtk
import packetlib
from packetlib import BasePacketClass, DataMismatchError, BaseAttrClass,\
	ArrayAttr

def shrtn(s,maxlen=20):
	return "%r%s"%(s[:20],"" if len(s)<20 else "...")

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
	cols=["name","repr","type"]
	cols_map=dict(map(reversed,enumerate(cols)))
	# mandatory
	def path_to_obj(self, path):
		cur=None
		for x in path:
			if cur is None and x==0: cur=self.packet
			else: cur=cur[x]
		return cur
	def on_get_flags(self):
		return 0
	def on_get_n_columns(self):
		return len(self.cols)
	def on_get_column_type(self, index):
		return str
	def on_get_iter(self, path):
		return path
	def on_get_path(self, rowref):
		return rowref
	def on_get_value(self, rowref, column):
		colname=self.cols[column]
		parent=self.path_to_obj(rowref[:-1])
		idx=rowref[-1]
		if parent is None and idx==0:
			if colname=="name": return "<Packet>"
			elif colname=="repr": return self.packet._repr()
			elif colname=="type": return self.packet.__class__.__name__
		if colname=="name":
			if isinstance(parent,ArrayAttr): return "[%d]"%idx
			field=parent._fields_[idx]
			try: return field.name
			except AttributeError: return "const[%d]"%idx
		elif colname=="repr":
			obj=parent[idx]
			if isinstance(obj,str): return "[%d]=%s"%(idx,shrtn(obj))
			return obj._repr()
		elif colname=="type":
			obj=parent[idx]
			return type(obj).__name__
		raise NotImplementedError("on_get_value", (rowref,colname))
	def on_iter_next(self, rowref):
		if rowref==(0,): return None
		idx=rowref[-1]
		if self.on_iter_n_children(rowref[:-1])>idx+1:
			return rowref[:-1]+(idx+1,)
		else: return None
	def on_iter_children(self, parent):
		return parent+(0,)
	def on_iter_has_child(self, rowref):
		obj=self.path_to_obj(rowref)
		return isinstance(obj,(BasePacketClass,ArrayAttr))
	def on_iter_n_children(self, rowref):
		obj=self.path_to_obj(rowref)
		if isinstance(obj, ArrayAttr):
			try: return obj.count
			except AttributeError:
				return sum(map(lambda x:1,obj))
		return len(obj._fields_.flow)
	def on_iter_nth_child(self, parent, n):
		if parent is None and n==0: return (0,)
		return parent+(n,)
	def on_iter_parent(self, child):
		return child[:-1]
	# end of mandatory methods
	def __init__(self, packet):
		self.packet=packet
		super(PacketTreeModel, self).__init__()


class GtkUI(object):
	def __getattr__(self,key):
		if not key.startswith('_'): print >>sys.stderr,"No attribute: %s"%(key)
		raise AttributeError,"No %r attribute"%(key)
	def __init__(self):
		self.ui=GtkBuilderUI(os.path.join(os.path.dirname(__file__),'gui.ui'),self)
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
		self.ui.pktree.set_model(None)
		if self.pclass is not None and self.data is not None:
			try: packet=self.pclass(self.data,self.data_offset)
			except DataMismatchError: pass
			else: self.ui.pktree.set_model(PacketTreeModel(packet))
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
	import pdb
	sys.excepthook=lambda exctype, value, traceback: pdb.post_mortem(traceback if traceback else sys.exc_info()[2])
	ui.run()
