#!/usr/bin/env python3
#
# Author:
#  Tamas Jos (@skelsec)
#

import enum
import io
import structures
import struct


class LSA_SECRET_BLOB:
	def __init__(self):
		self.legnth = None
		self.unk = None
		self.secret = None
		#self.remaining = None
	
	@staticmethod
	def from_bytes(data):
		return LSA_SECRET_BLOB.from_buffer(io.BytesIO(data))

	@staticmethod
	def from_buffer(buff):
		sk = LSA_SECRET_BLOB()
		sk.legnth = struct.unpack('<I', buff.read(4))
		sk.unk = buff.read(12)
		sk.secret = buff.read(sk.legnth)
		return sk
		
	def __str__(self):
		t = '== LSA_SECRET_BLOB ==\r\n'
		for k in self.__dict__:
			if isinstance(self.__dict__[k], list):
				for i, item in enumerate(self.__dict__[k]):
					t += '   %s: %s: %s' % (k, i, str(item))
			else:
				t += '%s: %s \r\n' % (k, str(self.__dict__[k]))
		return t
		
		
class LSA_SECRET:
	def __init__(self):
		self.version = None
		self.enc_key_id = None
		self.enc_algo = None
		self.flags = None
		self.data = None
	
	@staticmethod
	def from_bytes(data):
		return LSA_SECRET.from_buffer(io.BytesIO(data))

	@staticmethod
	def from_buffer(buff):
		sk = LSA_SECRET()
		sk.version = struct.unpack('<I', buff.read(4))
		sk.enc_key_id = buff.read(16)
		sk.enc_algo = struct.unpack('<I', buff.read(4))
		sk.flags = struct.unpack('<I', buff.read(4))
		sk.data = buff.read()
		
		return sk
		
	def __str__(self):
		t = '== LSA_SECRET ==\r\n'
		for k in self.__dict__:
			if isinstance(self.__dict__[k], list):
				for i, item in enumerate(self.__dict__[k]):
					t += '   %s: %s: %s' % (k, i, str(item))
			else:
				t += '%s: %s \r\n' % (k, str(self.__dict__[k]))
		return t
		
class LSA_SECRET_XP:
	def __init__(self):
		self.legnth = None
		self.version = None
		self.secret = None

	@staticmethod
	def from_bytes(data):
		return LSA_SECRET_XP.from_buffer(io.BytesIO(data))

	@staticmethod
	def from_buffer(buff):
		sk = LSA_SECRET_XP()		
		sk.legnth = struct.unpack('<I', buff.read(4))
		sk.version = struct.unpack('<I', buff.read(4))
		sk.secret = buff.read(sk.legnth)
		
		return sk
		
	def __str__(self):
		t = '== LSA_SECRET_XP ==\r\n'
		for k in self.__dict__:
			if isinstance(self.__dict__[k], list):
				for i, item in enumerate(self.__dict__[k]):
					t += '   %s: %s: %s' % (k, i, str(item))
			else:
				t += '%s: %s \r\n' % (k, str(self.__dict__[k]))
		return t
		
		
class NL_RECORD:
	def __init__(self):
		self.UserLength = None
		self.DomainNameLength = None
		self.EffectiveNameLength = None
		self.FullNameLength = None
		self.LogonScriptName = None
		self.ProfilePathLength = None
		self.HomeDirectoryLength = None
		self.HomeDirectoryDriveLength = None
		self.UserId = None
		self.PrimaryGroupId = None
		self.GroupCount = None
		self.logonDomainNameLength = None
		self.unk0 = None
		self.LastWrite = None
		self.Revision = None
		self.SidCount = None
		self.Flags = None
		self.unk1 = None
		self.LogonPackageLength = None
		self.DnsDomainNameLength = None
		self.UPN = None
		self.IV = None
		self.CH = None
		self.EncryptedData = None
		
	@staticmethod
	def from_bytes(data):
		return NL_RECORD.from_buffer(io.BytesIO(data))

	@staticmethod
	def from_buffer(buff):
		nl = NL_RECORD()		
		nl.UserLength = struct.unpack('<H', buff.read(2))
		nl.DomainNameLength = struct.unpack('<H', buff.read(2))
		nl.EffectiveNameLength = struct.unpack('<H', buff.read(2))
		nl.FullNameLength = struct.unpack('<H', buff.read(2))
		nl.LogonScriptName = struct.unpack('<H', buff.read(2))
		nl.ProfilePathLength = struct.unpack('<H', buff.read(2))
		nl.HomeDirectoryLength = struct.unpack('<H', buff.read(2))
		nl.HomeDirectoryDriveLength = struct.unpack('<H', buff.read(2))
		nl.UserId = struct.unpack('<I', buff.read(4))
		nl.PrimaryGroupId = struct.unpack('<I', buff.read(4))
		nl.GroupCount = struct.unpack('<I', buff.read(4))
		nl.logonDomainNameLength = struct.unpack('<H', buff.read(2))
		nl.unk0 = struct.unpack('<H', buff.read(2))
		nl.LastWrite = struct.unpack('<Q', buff.read(8))
		nl.Revision = struct.unpack('<I', buff.read(4))
		nl.SidCount = struct.unpack('<I', buff.read(4))
		nl.Flags = struct.unpack('<I', buff.read(4))
		nl.unk1 = struct.unpack('<I', buff.read(4))
		nl.LogonPackageLength = struct.unpack('<I', buff.read(4))
		nl.DnsDomainNameLength = struct.unpack('<H', buff.read(2))
		nl.UPN = struct.unpack('<H', buff.read(2))
		nl.IV = buff.read(16)
		nl.CH = buff.read(16)
		nl.EncryptedData = buff.read()
		
		return nl
		
	def __str__(self):
		t = '== NL_RECORD ==\r\n'
		for k in self.__dict__:
			if isinstance(self.__dict__[k], list):
				for i, item in enumerate(self.__dict__[k]):
					t += '   %s: %s: %s' % (k, i, str(item))
			else:
				t += '%s: %s \r\n' % (k, str(self.__dict__[k]))
		return t