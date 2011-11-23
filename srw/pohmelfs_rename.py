import struct

offset = 0
size = 0
# do not read csum
ioflags_read = 256
ioflags_write = 0
# do not lock operation, since we are 'inside' DNET_CMD_EXEC command already
aflags = 16
column = 0
group_id = 0

d = {'script' : 'insert', 'dentry_name' : pohmelfs_dentry_name}

def pohmelfs_upload_dentry(new_dir_id, new_name, inode_info):
	s = sstable()
	try:
		dir_content = n.read_data(new_dir_id, offset, size, aflags, ioflags_read)
		s.load(dir_content)
	except:
		#s.init(len(inode_info))
		s.init(256 + len(inode_info) + 8)

	s.insert(new_name, inode_info, True)
	content = str(s.save())

	n.write_data(new_dir_id, content, offset, aflags, ioflags_write)
	n.write_metadata(new_dir_id, '', pohmelfs_groups)
	
	logging.info("uploaded directory content hosting new name %s", new_name, extra=d)

try:
	binary_data = __input_binary_data_tuple[0]
	old_dir_id = elliptics_id(list(binary_data[0:64]), group_id, column)
	new_dir_id = elliptics_id(list(binary_data[64:128]), group_id, column)

	len_buf = struct.unpack_from("<I", buffer(binary_data), 128);
	new_name_len = int(len_buf[0])
	new_name = str(binary_data[132:])

	s = sstable()
	dir_content = n.read_data(old_dir_id, offset, size, aflags, ioflags_read)
	s.load(dir_content)

	ret = s.search(pohmelfs_dentry_name)
	if not ret:
		raise KeyError("no entry")

	inode_info = bytearray(ret[1])
	inode_info[84:88] = binary_data[128:132]

	if binary_data[0:64] != binary_data[64:128]:
		pohmelfs_upload_dentry(new_dir_id, new_name, inode_info)
	else:
		s.insert(new_name, inode_info, True)

	s.delete(pohmelfs_dentry_name)
	content = str(s.save())

	n.write_data(old_dir_id, content, offset, aflags, ioflags_write)
	n.write_metadata(old_dir_id, '', pohmelfs_groups)

	__return_data = 'ok'
	logging.info("renamed -> %s", new_name, extra=d)
except KeyError as e:
	logging.error("key error: %s", e.__str__(), extra=d)
	__return_data = 'key error: ' + e.__str__()
except Exception as e:
	logging.error("generic error: %s", e.__str__(), extra=d)
	__return_data = 'error: ' + e.__str__()
