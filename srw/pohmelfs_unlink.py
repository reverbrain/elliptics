d = {'script' : 'unlink', 'dentry_name' : pohmelfs_dentry_name}

try:
	binary_data = __input_binary_data_tuple[0]
	parent_id = elliptics_id(list(binary_data[0:64]), pohmelfs_group_id, pohmelfs_column)

	s = sstable()
	dir_content = n.read_data(parent_id, pohmelfs_offset, pohmelfs_size, pohmelfs_aflags, pohmelfs_ioflags_read)
	s.load(dir_content)

	ret = s.search(pohmelfs_dentry_name)
	if not ret:
		raise KeyError("no entry")

	payload = ret[1]
	obj_id = elliptics_id(list(bytearray(payload[0:64])), pohmelfs_group_id, -1)

	n.remove(obj_id, pohmelfs_aflags)

	s.delete(pohmelfs_dentry_name)
	content = str(s.save())

	pohmelfs_write(parent_id, content)
	__return_data = 'ok'

	logging.info("removed", extra=d)

except KeyError as e:
	logging.error("key error: %s", e.__str__(), extra=d)
	__return_data = 'key error: ' + e.__str__()
except Exception as e:
	logging.error("generic error: %s", e.__str__(), extra=d)
	__return_data = 'error: ' + e.__str__()
