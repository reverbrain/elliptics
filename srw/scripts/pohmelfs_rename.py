import struct

d = {'script' : 'rename', 'dentry_name' : pohmelfs_dentry_name}

def pohmelfs_upload_dentry(new_dir_id, new_name, inode_info):
	s = sstable()
	try:
		dir_content = n.read_data(new_dir_id, pohmelfs_offset, pohmelfs_size, pohmelfs_aflags, pohmelfs_ioflags_read)
		s.load(dir_content)
	except:
		if not ': -2' in str(e):
			raise
		s.init(len(inode_info))

	s.insert(new_name, inode_info, True)
	content = str(s.save())

	pohmelfs_write(new_dir_id, content)
	
	logging.info("uploaded directory content hosting new name %s", new_name, extra=d)

try:
	binary_data = __input_binary_data_tuple[0]
	old_dir_id = elliptics_id(list(binary_data[0:64]), pohmelfs_group_id, pohmelfs_column)
	new_dir_id = elliptics_id(list(binary_data[64:128]), pohmelfs_group_id, pohmelfs_column)
	d['object'] = dump_id(old_dir_id) + ' -> ' + dump_id(new_dir_id)

	inode_info = binary_data[128:128+80]
	new_name = str(binary_data[128+80:])

	s = sstable()
	dir_content = n.read_data(old_dir_id, pohmelfs_offset, pohmelfs_size, pohmelfs_aflags, pohmelfs_ioflags_read)
	s.load(dir_content)

	ret = s.search(pohmelfs_dentry_name)
	if not ret:
		raise KeyError("no entry")

	if binary_data[0:64] != binary_data[64:128]:
		pohmelfs_upload_dentry(new_dir_id, new_name, str(inode_info))
	else:
		s.insert(new_name, str(inode_info), True)

	s.delete(pohmelfs_dentry_name)
	content = str(s.save())

	pohmelfs_write(old_dir_id, content)

	__return_data = 'ok'
	#logging.info("renamed -> %s: %s", new_name, parse(content), extra=d)
	logging.info("renamed -> %s", new_name, extra=d)

	s = None
	content = None

	gc.collect()

except KeyError as e:
	logging.error("key error: %s", e.__str__(), extra=d)
	__return_data = 'key error: ' + e.__str__()
except Exception as e:
	logging.error("generic error: %s", e.__str__(), extra=d)
	__return_data = 'error: ' + e.__str__()
