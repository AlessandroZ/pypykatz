#!/usr/bin/env python3
#
# Author:
#  Tamas Jos (@skelsec)
#

import io
import enum
import struct

from pypykatz.commons.win_datatypes import GUID
from pypykatz.dpapi.structures.blob import DPAPI_BLOB


class VAULT_ATTRIBUTE_MAP_ENTRY:
	def __init__(self):
		self.id = None
		self.offset = None
		self.unk0 = None
	
	@staticmethod
	def from_bytes(data):
		return VAULT_ATTRIBUTE_MAP_ENTRY.from_buffer(io.BytesIO(data))

	@staticmethod
	def from_buffer(buff):
		sk = VAULT_ATTRIBUTE_MAP_ENTRY()		
		sk.id = struct.unpack('<I', buff.read(4))
		sk.offset = struct.unpack('<I', buff.read(4))
		sk.unk0 = struct.unpack('<I', buff.read(4))
		return sk
		
	def __str__(self):
		t = '== VAULT_ATTRIBUTE_MAP_ENTRY ==\r\n'
		for k in self.__dict__:
			if isinstance(self.__dict__[k], list):
				for i, item in enumerate(self.__dict__[k]):
					t += '   %s: %s: %s' % (k, i, str(item))
			else:
				t += '%s: %s \r\n' % (k, str(self.__dict__[k]))
		return t
		
class VAULT_ATTRIBUTE:
	def __init__(self):
		self.id = None
		self.unk0 = None
		self.unk1 = None
		self.unk2 = None
		
		self.padding = None
		self.unk3 = None
		
		self.size = None
		self.iv_present = None
		self.iv_size = None
		self.iv = None
		self.data = None
	
	@staticmethod
	def from_bytes(data):
		return VAULT_ATTRIBUTE.from_buffer(io.BytesIO(data))

	@staticmethod
	def from_buffer(buff):
		pos = buff.tell()
		buff.seek(-1, 2)
		size = buff.tell() - pos
		buff.seek(pos, 0)
		
		sk = VAULT_ATTRIBUTE()		
		sk.id = struct.unpack('<I', buff.read(4))
		sk.unk0 = struct.unpack('<I', buff.read(4))
		sk.unk1 = struct.unpack('<I', buff.read(4))
		sk.unk2 = struct.unpack('<I', buff.read(4))
		
		if size > 20:
			pos = buff.tell()
			test = buff.read(6)
			if test == b'\x00'*6:
				sk.padding = test
			else:
				buff.seek(pos, 0)
			
			if sk.id >= 100:
				sk.unk3 = struct.unpack('<I', buff.read(4))
				
		if size > 25:
			sk.size = struct.unpack('<I', buff.read(4))
			sk.iv_present = bool(buff.read(1)[0])
			if sk.iv_present:
				sk.iv_size = struct.unpack('<I', buff.read(4))
				sk.iv = buff.read(sk.iv_size)
				sk.data = buff.read(sk.size - (sk.iv_size + 5))
			else:
				sk.data = buff.read(sk.size - 1 )
		
		return sk
		
	def __str__(self):
		t = '== VAULT_ATTRIBUTE ==\r\n'
		for k in self.__dict__:
			if isinstance(self.__dict__[k], list):
				for i, item in enumerate(self.__dict__[k]):
					t += '   %s: %s: %s' % (k, i, str(item))
			else:
				t += '%s: %s \r\n' % (k, str(self.__dict__[k]))
		return t
	

class VAULT_VCRD:
	"""
	"""
	def __init__(self):
		self.schema_guid = None
		self.unk0 = None
		self.last_written = None
		self.unk1 = None
		self.unk2 = None
		self.friendlyname_length = None
		self.friendlyname = None
		self.attribute_maps_length = None
		self.attribute_maps = None
		
		self.vames = []
		self.attributes = []
		
	@staticmethod
	def from_bytes(data):
		return VAULT_VCRD.from_buffer(io.BytesIO(data))

	@staticmethod
	def from_buffer(buff):
		sk = VAULT_VCRD()		
		sk.schema_guid = GUID(buff).value
		sk.unk0 = struct.unpack('<I', buff.read(4))
		sk.last_written = struct.unpack('<Q', buff.read(8))
		sk.unk1 = struct.unpack('<I', buff.read(4))
		sk.unk2 = struct.unpack('<I', buff.read(4))
		sk.friendlyname_length = struct.unpack('<I', buff.read(4))
		sk.friendlyname = buff.read(sk.friendlyname_length)
		if sk.friendlyname_length > 0:
			try:
				sk.friendlyname = sk.friendlyname.decode('utf-16-le')
			except:
				pass
		sk.attribute_maps_length = struct.unpack('<I', buff.read(4))
		sk.attribute_maps = buff.read(sk.attribute_maps_length)
		
		sk.attributes = []
		db = io.BytesIO(sk.attribute_maps)
		for _ in range(sk.attribute_maps_length // 12):
			vame = VAULT_ATTRIBUTE_MAP_ENTRY.from_buffer(db)
			sk.vames.append(vame)
		
		i = 0
		while i < len(sk.vames) - 1:
			buff.seek(sk.vames[i].offset)
			data = buff.read(sk.vames[i+1].offset - sk.vames[i].offset)
			va = VAULT_ATTRIBUTE.from_bytes(data)
			sk.attributes.append(va)
			i+=1
		
		va = VAULT_ATTRIBUTE.from_buffer(buff)
		sk.attributes.append(va)
		return sk
		
	def __str__(self):
		t = '== VAULT_VCRD ==\r\n'
		for k in self.__dict__:
			if isinstance(self.__dict__[k], list):
				for i, item in enumerate(self.__dict__[k]):
					t += '   %s: %s: %s' % (k, i, str(item))
			else:
				t += '%s: %s \r\n' % (k, str(self.__dict__[k]))
		return t
		
class VAULT_VPOL:
	def __init__(self):
		self.version = None
		self.guid = None
		self.description_length = None
		self.description = None
		self.unk0 = None
		self.size = None
		self.guid2 = None
		self.guid3 = None
		self.key_size = None
		self.blob = None #encrypted VAULT_VPOL_KEYS
	
	@staticmethod
	def from_bytes(data):
		return VAULT_VPOL.from_buffer(io.BytesIO(data))

	@staticmethod
	def from_buffer(buff):
		sk = VAULT_VPOL()		
		sk.version = struct.unpack('<I', buff.read(4))
		sk.guid = GUID(buff).value
		sk.description_length = struct.unpack('<I', buff.read(4))
		sk.description = buff.read(sk.description_length)
		sk.unk0 = buff.read(12)
		sk.size = struct.unpack('<I', buff.read(4))
		sk.guid2 = GUID(buff).value
		sk.guid3 = GUID(buff).value
		sk.key_size = struct.unpack('<I', buff.read(4))
		sk.blob = DPAPI_BLOB.from_bytes(buff.read(sk.key_size))
		
		return sk
		
	def __str__(self):
		t = '== VAULT_VPOL ==\r\n'
		for k in self.__dict__:
			if isinstance(self.__dict__[k], list):
				for i, item in enumerate(self.__dict__[k]):
					t += '   %s: %s: %s' % (k, i, str(item))
			else:
				t += '%s: %s \r\n' % (k, str(self.__dict__[k]))
		return t		

class VAULT_VPOL_KEYS:
	def __init__(self):
		self.key1 = None
		self.key2 = None
	
	@staticmethod
	def from_bytes(data):
		return VAULT_VPOL_KEYS.from_buffer(io.BytesIO(data))

	@staticmethod
	def from_buffer(buff):
		sk = VAULT_VPOL_KEYS()
		res = []
		for _ in range(2):
			test = buff.read(1)
			buff.seek(-1,1)
			if test == b'\x24' or test == b'\x34':
				res.append(KDBM.from_buffer(buff))
			else:
				res.append(KSSM.from_buffer(buff))
		sk.key1 = res[0]
		sk.key2 = res[1]
		return sk
		
	def __str__(self):
		t = '== VAULT_VPOL_KEYS ==\r\n'
		for k in self.__dict__:
			if isinstance(self.__dict__[k], list):
				for i, item in enumerate(self.__dict__[k]):
					t += '   %s: %s: %s' % (k, i, str(item))
			else:
				t += '%s: %s \r\n' % (k, str(self.__dict__[k]))
		return t		
		
class KDBM:
	def __init__(self):
		self.size = None
		self.version = None
		self.unk0 = None
		self.keyblob = None
		
	def get_key(self):
		return self.keyblob.key
	
	@staticmethod
	def from_bytes(data):
		return KDBM.from_buffer(io.BytesIO(data))

	@staticmethod
	def from_buffer(buff):
		from pypykatz.commons.common import hexdump
		sk = KDBM()		
		sk.size = struct.unpack('<I', buff.read(4))
		sk.version = struct.unpack('<I', buff.read(4))
		sk.unk0 = struct.unpack('<I', buff.read(4))
		sk.keyblob = BCRYPT_KEY_DATA_BLOB_HEADER.from_bytes(buff.read(sk.size - 8))		
		return sk
		
	def __str__(self):
		t = '== KDBM ==\r\n'
		for k in self.__dict__:
			if isinstance(self.__dict__[k], list):
				for i, item in enumerate(self.__dict__[k]):
					t += '   %s: %s: %s' % (k, i, str(item))
			else:
				t += '%s: %s \r\n' % (k, str(self.__dict__[k]))
		return t
		
class KSSM:
	def __init__(self):
		self.size = None
		self.version = None
		self.unk0 = None
		self.keyblob = None
		
	def get_key(self):
		return self.keyblob
	
	@staticmethod
	def from_bytes(data):
		return KSSM.from_buffer(io.BytesIO(data))

	@staticmethod
	def from_buffer(buff):
		sk = KSSM()
		sk.size = struct.unpack('<I', buff.read(4))
		sk.version = struct.unpack('<I', buff.read(4))
		sk.unk0 = struct.unpack('<I', buff.read(4))
		sk.keyblob = buff.read(sk.size - 8)
		
		return sk
		
	def __str__(self):
		t = '== KSSM ==\r\n'
		for k in self.__dict__:
			if isinstance(self.__dict__[k], list):
				for i, item in enumerate(self.__dict__[k]):
					t += '   %s: %s: %s' % (k, i, str(item))
			else:
				t += '%s: %s \r\n' % (k, str(self.__dict__[k]))
		return t
		
class BCRYPT_KEY_DATA_BLOB_HEADER:
	def __init__(self):
		self.magic = None
		self.version = None
		self.key_data= None
		self.key = None
	
	@staticmethod
	def from_bytes(data):
		return BCRYPT_KEY_DATA_BLOB_HEADER.from_buffer(io.BytesIO(data))

	@staticmethod
	def from_buffer(buff):
		sk = BCRYPT_KEY_DATA_BLOB_HEADER()
		sk.magic = struct.unpack('<I', buff.read(4))
		sk.version = struct.unpack('<I', buff.read(4))
		sk.key_data = struct.unpack('<I', buff.read(4))
		sk.key = buff.read(sk.key_data)
		
		return sk
		
	def __str__(self):
		t = '== BCRYPT_KEY_DATA_BLOB_HEADER ==\r\n'
		for k in self.__dict__:
			if isinstance(self.__dict__[k], list):
				for i, item in enumerate(self.__dict__[k]):
					t += '   %s: %s: %s' % (k, i, str(item))
			else:
				t += '%s: %s \r\n' % (k, str(self.__dict__[k]))
		return t