#!/usr/bin/python

import os,sys,imp
os.environ["LC_CTYPE"]="en_US.utf8"
import gtk, pango
import packetlib
from packetlib import BasePacketClass, DataMismatchError, BaseAttrClass,\
	ArrayAttr, IntValSZ
import code
import re


def shrtn(s,maxlen=20):
	return "%r%s"%(s[:20],"" if len(s)<20 else "...")

class HexTextView(object):
	to_hex_re=re.compile(r'([\s\S]{0,16})')
	no_disp_re=re.compile(r'[\x00-\x1f\x7f-\xff]')
	def __init__(self, offset_view, hex_view, ascii_view, sbar):
		self.hex=hex_view.get_buffer()
		self.offsets=offset_view.get_buffer()
		self.ascii=ascii_view.get_buffer()
		self.ascii.connect("mark-set",self.on_ascii_sel)
		self.hex.connect("mark-set",self.on_hex_sel)
		fontdesc = pango.FontDescription("Monospace 10")
		self.rcstyle=hex_view.rc_get_style()
		self.int_le=self.int_be=self.sel_ofs=None
		self.sbar=sbar
		self.sbar_ctx=sbar.get_context_id("hextext")
		for view in offset_view, hex_view, ascii_view:
			view.modify_font(fontdesc)
		self.init_tags_n_marks()
	def init_tags_n_marks(self):
		self.hex.create_tag("sz_end",background="#f00")
		for buf in self.hex, self.ascii:
			buf.create_tag("sel",
				background_gdk=self.rcstyle.base[gtk.STATE_SELECTED],
				foreground_gdk=self.rcstyle.fg[gtk.STATE_SELECTED],
				)
		ascii_start=self.ascii.get_bounds()[0]
		self.sz_mark_le=self.ascii.create_mark(None, ascii_start, True)
		self.sz_mark_be=self.ascii.create_mark(None, ascii_start, True)
	def ascii_i2o(self, textiter):
		return textiter.get_line()*16+textiter.get_line_offset()
	def hex_o2i(self, ofs):
		return self.hex.get_iter_at_line_offset(ofs/16,(ofs%16)*3)
	def ascii_o2i(self, ofs):
		return self.ascii.get_iter_at_line_offset(ofs/16,(ofs%16))
	def hex_i2o(self, textiter):
		return textiter.get_line()*16+(textiter.get_line_offset()+1)/3
	def show_sz_offsets(self, data_offset):
		hex_bounds=self.hex.get_bounds()
		last_off=self.hex_i2o(hex_bounds[1])
		self.hex.remove_tag_by_name("sz_end", *hex_bounds)
		for mark,intval in (self.sz_mark_le,self.int_le), (self.sz_mark_be,self.int_be):
			mark.set_visible(False)
			size_off=data_offset+intval
			if size_off<=last_off:
				self.ascii.move_mark(mark,self.ascii_o2i(size_off))
				mark.set_visible(True)
				off_iter_en=self.hex_o2i(size_off)
				off_iter_st=off_iter_en.copy()
				if off_iter_st.backward_char():
					self.hex.apply_tag_by_name("sz_end",off_iter_st,off_iter_en)
				else:
					print "Could not move iter backwards"
	def update_sbar(self):
		self.sbar.remove_all(self.sbar_ctx)
		msg=[]
		if self.sel_ofs:
			msg.append("[{0}:{1}] [{0:#x}:{1:#x}]".format(*self.sel_ofs))
		if self.int_le is not None: msg.append("LE:{0},{0:#x}".format(self.int_le))
		if self.int_be is not None: msg.append("BE:{0},{0:#x}".format(self.int_be))
		self.sbar.push(self.sbar_ctx, " ".join(msg))
	def on_hex_sel(self, buf, textiter, mark):
		sel_bounds=buf.get_selection_bounds()
		self.ascii.remove_tag_by_name("sel", *self.ascii.get_bounds())
		if sel_bounds:
			self.sel_ofs=map(self.hex_i2o,sel_bounds)
			self.ascii.apply_tag_by_name("sel",*map(self.ascii_o2i,self.sel_ofs))
			sel_txt=self.hex.get_text(*sel_bounds).replace(" ","").replace("\n","")
			if len(sel_txt)%2==0 and len(sel_txt)<=16:
				int_data=sel_txt.decode("hex")
				self.int_le=IntValSZ(int_data,0,len(int_data)).value
				self.int_be=IntValSZ._c(le=False)(int_data,0,len(int_data)).value
				self.show_sz_offsets(self.sel_ofs[1])
			else:
				self.int_le=self.int_be=None
			self.update_sbar()
	def on_ascii_sel(self, buf, textiter, mark):
		sel_bounds=map(self.ascii_i2o,buf.get_selection_bounds())
		self.hex.remove_tag_by_name("sel", *self.hex.get_bounds())
		if sel_bounds:
			self.hex.apply_tag_by_name("sel",*map(self.hex_o2i,sel_bounds))
	def set_text(self, txt):
		for buf in self.hex, self.offsets, self.ascii:
			buf.set_text("")
		nl=""
		for offs,hexstr,ascii in self.iter_lines(txt):
			self.offsets.insert_at_cursor("%s%08x"%(nl,offs))
			self.hex.insert_at_cursor("%s%s"%(nl,hexstr))
			self.ascii.insert_at_cursor("%s%s"%(nl,ascii))
			if not nl: nl="\n"
	def iter_lines(self, s):
		for idx,match in enumerate(self.to_hex_re.finditer(s)):
			line=match.group(0)
			if not line: continue
			yield (idx*16,
				" ".join(map(lambda c: "%02x"%ord(c), line))+"   "*(16-len(line)),
				"".join(map(lambda c: c if not self.no_disp_re.match(c) else u"\u00b7", line)))
	
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
			if isinstance(obj,str): return shrtn(obj)
			return obj._repr()
		elif colname=="type":
			obj=parent[idx]
			if isinstance(obj,str): return "%s[%d]"%(type(obj).__name__,len(obj))
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
		self.ui.pktree.insert_column_with_attributes(-1,'Name',gtk.CellRendererText(),text=0)
		self.ui.pktree.insert_column_with_attributes(-1,'Type',gtk.CellRendererText(),text=2)
		self.ui.pktree.insert_column_with_attributes(-1,'Value',gtk.CellRendererText(),text=1)
		self.reset()
		self.module_load_count=0
		self.imp_suffixes=dict([(x[0],x) for x in imp.get_suffixes()])
		self.hexview=HexTextView(self.ui.info_offset, self.ui.info_hex, self.ui.info_ascii, self.ui.hex_sbar)
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
	def on_cmd_activate(self, entry):
		try: co=code.compile_command(entry.get_text())
		except Exception,e:
			print "Exception when compiling code:",e
		else:
			print "Running:",entry.get_text()
			try:
				if co is not None: exec co
			except Exception,e:
				print "Exception when running code:",e
	def on_pktree_cursor_changed(self, tv):
		cur_path,cur_col=tv.get_cursor()
		if cur_path is None:
			self.hexview.set_text(None)
		else:
			self.hexview.set_text(str(self.ui.pktree.get_model().path_to_obj(cur_path)))
	def on_reload_pmod_clicked(self, btn):
		exp=[]
		self.ui.pktree.map_expanded_rows(lambda tv,path: exp.append(path))
		self.load_pfile(self.parser_fname)
		self.set_pclass(self.pclass.__name__)
		for path in exp:
			self.ui.pktree.expand_row(path, False)
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
		try: self.pclass=getattr(self.pmod,clsname)
		except AttributeError: self.ui.pktree.set_model(None)
		else: self.reload()
	def on_pname(self,entry): self.set_pclass(entry.child.get_text())
	def load_pfile(self,fname):
		self.pmod=imp.load_module("pmodule_%d"%self.module_load_count,open(fname),fname,self.imp_suffixes[fname[fname.rindex("."):]])
		self.module_load_count+=1
		self.ui.pname_store.clear()
		for name in dir(self.pmod):
			obj=getattr(self.pmod,name)
			if type(obj)==type(packetlib.BasePacketClass) and issubclass(obj, packetlib.BasePacketClass) and obj is not packetlib.BasePacketClass:
				self.ui.pname_store.append((obj.__name__,))
	def on_pfile_file_set(self,fchooser):
		self.parser_fname=fchooser.get_filename()
		self.load_pfile(self.parser_fname)

if __name__=='__main__':
	ui=GtkUI()
	if len(sys.argv)>1:
		ui.parser_fname,pclass=sys.argv[1].split(":")
		ui.load_pfile(ui.parser_fname)
		ui.set_pclass(pclass)
	if len(sys.argv)>2: ui.set_file(sys.argv[2])
	#import pdb
	#sys.excepthook=lambda exctype, value, traceback: pdb.post_mortem(traceback if traceback else sys.exc_info()[2])
	ui.run()
