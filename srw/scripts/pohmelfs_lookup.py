d = {'script' : 'lookup', 'dentry_name' : pohmelfs_dentry_name}

try:
	binary_data = __input_binary_data_tuple[0]
	parent_id = elliptics_id(list(binary_data[0:64]), pohmelfs_group_id, pohmelfs_column)
	d['object'] = 'parent: ' + dump_id(parent_id)

	s = sstable()

	dir_content = n.read_data(parent_id, pohmelfs_offset, pohmelfs_size, pohmelfs_aflags, pohmelfs_ioflags_read)
	s.load(dir_content)

	ret = s.search(pohmelfs_dentry_name)
	if not ret:
		raise KeyError("no entry")

	id_data = bytearray(ret[1])
	obj_id = elliptics_id(list(id_data[0:64]), pohmelfs_group_id, pohmelfs_inode_info_column)
	__return_data = n.read_data(obj_id, pohmelfs_offset, pohmelfs_size, pohmelfs_aflags, pohmelfs_ioflags_read)

	s = None
	dir_content = None
	ret = None
	s = None

	gc.collect()

	logging.error("found: %s", pohmelfs_dentry_name, extra=d)

except KeyError as e:
	logging.error("key error: %s", e.__str__(), extra=d)
	__return_data = ''
except Exception as e:
	if 'Incorrect header magic' in str(e):
		parent_id.type = -1
		n.remove(parent_id, pohmelfs_aflags)
		raise KeyError("no entry")
	else:
		logging.error("generic error: %s", e.__str__(), extra=d)
		__return_data = 'error: ' + e.__str__()
