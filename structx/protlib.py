#!/usr/bin/python

import socket,select
from packetlib import DynamicAttrClass

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
