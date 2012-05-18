#!/usr/bin/python

import socket,select
from packetlib import DynamicAttrClass
import sys

class NetworkError(Exception): pass
class TimeoutError(NetworkError): pass
class ConnectTimeout(TimeoutError): pass
class ReceiveTimeout(TimeoutError): pass
class SendTimeout(TimeoutError): pass
class ProtocolError(NetworkError): pass

class TcpClient(DynamicAttrClass):
	_defaults=dict(connect_tmout=None,recv_tmout=None,send_tmout=None,recv_flags=0)
	__slots__=['recv_bufsize','host','port','connection','sock']+_defaults.keys()
	def get_sock(self):
		sock=socket.socket()
		self.recv_bufsize=sock.getsockopt(socket.SOL_SOCKET,socket.SO_RCVBUF)
		sock.settimeout(self.connect_tmout)
		sock.connect((self.host,self.port))
		sock.settimeout(self.recv_tmout)
		return sock
	def read(self):
		if self.sock in select.select([self.sock],[],[],self.recv_tmout)[0]:
			read_buf=[self.sock.recv(self.recv_bufsize)]
			while self.sock in select.select([self.sock],[],[],0)[0]:
				read_buf.append(self.sock.recv(self.recv_bufsize))
			return ''.join(read_buf)
		raise ReceiveTimeout
	def write(self,data):
		offset=0
		while offset<len(data) and self.sock in select.select([],[self.sock],[],self.send_tmout)[1]:
			offset=offset+self.sock.send(data[offset:])
		return offset
	def shutdown(self):
		if self.is_connected():
			try: self.sock.shutdown(2)
			except socket.error: pass
			self.sock.close()
			del self.sock
	def is_connected(self):
		try: sock=object.__getattribute__(self,'sock')
		except AttributeError: return False
		try: sock.send('')
		except socket.error: return False
		return True

class PatFinder(object):
	read_size=256*1024
	class Match(object):
		__slots__=["_match", "name", "check"]
		def __init__(self, match, name, check):
			self._match=match
			self.name=name
			self.check=check
		def __getattr__(self, key):
			return getattr(self._match, key)
		def __getitem__(self, key):
			return self._match.group(key)
	def __init__(self, *checks, **attr):
		self.checks=checks
		for k,v in attr.iteritems(): setattr(self, k, v)
	def data_skipped(self, data):
		print >>sys.stderr,"Skipped data: %r"%(data,)
	def search(self, data):
			ret_st=ret=ret_check=ret_idx=None
			for idx,check in enumerate(self.checks):
				if isinstance(check, tuple): idx,check=check
				match=check.search(data)
				if match:
					st=match.start()
					if ret is None or st<ret_st:
						ret,ret_check,ret_st,ret_idx=match,check,st,idx
			if ret_st:
				self.data_skipped(data[:ret_st])
			if ret is not None:
				return self.Match(ret,check=ret_check,name=ret_idx)
	def read_func(self, data_src):
		return data_src.read(self.read_size)
	def finditer(self, data_src, read_func=None):
		remaining_buffer=""
		if read_func is None: read_func=self.read_func
		while True:
			match=self.search(remaining_buffer)
			if match is not None:
				remaining_buffer=remaining_buffer[match.end():]
				yield match
			if match is None or not remaining_buffer:
				data=read_func(data_src)
				if data=="":
					if remaining_buffer:
						self.data_skipped(remaining_buffer)
					return
				remaining_buffer+=data