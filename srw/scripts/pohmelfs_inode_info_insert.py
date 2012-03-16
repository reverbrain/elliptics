d = {'script' : 'insert', 'dentry_name' : pohmelfs_dentry_name}

try:
	binary_data = __input_binary_data_tuple[0]
	parent_id = elliptics_id(list(binary_data[0:64]), pohmelfs_group_id, pohmelfs_column)
	obj_id = elliptics_id(list(binary_data[64:128]), pohmelfs_group_id, pohmelfs_column)
	inode_info = str(binary_data[64:])
	d['object'] = 'parent: ' + dump_id(parent_id) + ', object: ' + dump_id(obj_id)

	s = sstable()
	dir_content = ''
	try:
		dir_content = n.read_data(parent_id, pohmelfs_offset, pohmelfs_size, pohmelfs_aflags, pohmelfs_ioflags_read)
		s.load(dir_content)
	except Exception as e:
		if not ': -2' in str(e):
			raise
		# size of pohmelfs_dentry_disk structure
		s.init(80)

	s.insert(pohmelfs_dentry_name, inode_info, True)
	content = str(s.save())

	pohmelfs_write(parent_id, content)
	logging.info("inserted", extra=d)

	s = None
	content = None
	dir_content = None

	gc.collect()

	__return_data = 'ok'
except KeyError as e:
	logging.error("key error: %s", e.__str__(), extra=d)
	__return_data = 'key error: ' + e.__str__()
except Exception as e:
	if 'Incorrect header magic' in str(e):
		parent_id.type = -1
		n.remove(parent_id, pohmelfs_aflags)

		s = sstable()
		s.init(len(inode_info))
		s.insert(pohmelfs_dentry_name, inode_info, True)
		content = str(s.save())

		pohmelfs_write(parent_id, content)
		logging.info("inserted", extra=d)
		__return_data = 'ok'
	else:
		logging.error("generic error: %s", e.__str__(), extra=d)
		__return_data = 'error: ' + e.__str__()
