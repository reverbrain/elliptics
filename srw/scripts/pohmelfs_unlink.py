d = {'script' : 'unlink', 'dentry_name' : pohmelfs_dentry_name}

try:
	binary_data = __input_binary_data_tuple[0]
	parent_id = elliptics_id(list(binary_data[0:64]), pohmelfs_group_id, pohmelfs_column)
	d['object'] = 'parent: ' + dump_id(parent_id)

	s = sstable()
	dir_content = n.read_data(parent_id, pohmelfs_offset, pohmelfs_size, pohmelfs_aflags, pohmelfs_ioflags_read)

	s.load(dir_content)
	s.delete(pohmelfs_dentry_name)
	content = str(s.save())

	pohmelfs_write(parent_id, content)
	__return_data = 'ok'

	logging.info("done", extra=d)

	s = None
	dir_content = None

	gc.collect()

except KeyError as e:
	logging.error("key error: %s", e.__str__(), extra=d)
	__return_data = 'key error: ' + e.__str__()
except Exception as e:
	logging.error("generic error: %s", e.__str__(), extra=d)
	__return_data = 'error: ' + e.__str__()
