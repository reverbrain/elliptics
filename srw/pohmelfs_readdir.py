d = {'script' : 'readdir', 'dentry_name' : pohmelfs_dentry_name}

def readdir_parse(buffer):
	# Header format:
	# 8 bytes: magic
	# 2 bytes: version
	# 2 bytes: chunk size
	# 4 bytes: number of chunks inside
	header_fmt = "<8sHHI"

	# Chunk header format:
	# 2 bytes: length in chunks
	# 2 bytes: current chunk
	# 2 bytes: key size
	# 2 bytes: payload size
	chunk_header_fmt = "<HHHH"
	chunk_header_size = 8

	# Parse header
	position = 0
	header = struct.unpack_from(header_fmt, buffer, position)
	position += struct.calcsize(header_fmt)

	header_chunk_size = header[2]
	header_count = header[3]
	header_strings_start = position

	keys = []
	#print "chunk size:", header_chunk_size, ", chunks count:", header_count, ", strings start at", header_strings_start

	offset = header_strings_start
	while offset < header_strings_start + header_count * header_chunk_size:
		chunk_header = struct.unpack_from(chunk_header_fmt, buffer, offset)
		if chunk_header[1] > 0:
			offset -= chunk_header[1]*header_chunk_size

		chunk_header = struct.unpack_from(chunk_header_fmt, buffer, offset)

		key_len = chunk_header[2]
		payload_len = chunk_header[3]

		key = ""
		payload = ""
		rec_offset = 0

		for i in xrange(0, chunk_header[0]):
			key_size = 0

			# Get key from chunks
			if key_len > 0:
				key_size = header_chunk_size - chunk_header_size
				if key_len < key_size:
					key_size = key_len

				key_offset = offset + rec_offset + chunk_header_size
				key += buffer[key_offset:(key_offset + key_size)]
				key_len -= key_size

			# Get payload from chunks
			if key_len == 0 and payload_len > 0:
				payload_size = header_chunk_size - chunk_header_size - key_size
				if payload_len < payload_size:
					payload_size = payload_len

				payload_offset = offset + rec_offset + chunk_header_size + key_size
				payload += buffer[payload_offset:(payload_offset + payload_size)]
				payload_len -= payload_size

			rec_offset += header_chunk_size
		keys.append((key, payload))
		#print key, payload
		offset += chunk_header[0]*header_chunk_size
	
	return keys

try:
	binary_data = __input_binary_data_tuple[0]
	parent_id = elliptics_id(list(binary_data[0:64]), pohmelfs_group_id, pohmelfs_column)
	max_size, fpos = struct.unpack_from('<II', buffer(binary_data), 64)

	dir_content = n.read_data(parent_id, pohmelfs_offset, pohmelfs_size, pohmelfs_aflags, pohmelfs_ioflags_read)

	pos = 0
	ret = ''
	dirs = readdir_parse(dir_content)
	for dir in dirs:
		key = dir[0]
		bd = dir[1]

		pos += 1
		if pos > fpos:
			mode = struct.unpack_from("<I", buffer(bd), 64)[0]
			ino = struct.unpack_from("<Q", buffer(bd), 88)[0]

			dentry = struct.pack('<QBBHI', ino, (mode >> 12) & 15, len(key), 0, 0)
			if len(ret) + len(dentry) + len(key) <= max_size:
				ret += str(dentry) + key
			else:
				break

	__return_data = ret

	logging.info("readdir completed, sending %d entries (%d bytes)", pos - fpos, len(ret), extra=d)
	gc.collect()

except KeyError as e:
	logging.error("key error: %s", e.__str__(), extra=d)
	__return_data = ''
except Exception as e:
	logging.error("generic error: %s", e.__str__(), extra=d)
	__return_data = ''

