d = {'script' : 'lookup', 'dentry_name' : pohmelfs_dentry_name}

try:
	binary_data = __input_binary_data_tuple[0]
	parent_id = elliptics_id(list(binary_data[0:64]), pohmelfs_group_id, pohmelfs_column)

	s = sstable()

	dir_content = n.read_data(parent_id, pohmelfs_offset, pohmelfs_size, pohmelfs_aflags, pohmelfs_ioflags_read)
	s.load(dir_content)

	ret = s.search(pohmelfs_dentry_name)
	if not ret:
		raise KeyError("no entry")
	__return_data = str(ret[1])
except KeyError as e:
	logging.error("key error: %s", e.__str__(), extra=d)
	__return_data = 'key error: ' + e.__str__()
except Exception as e:
	logging.error("generic error: %s", e.__str__(), extra=d)
	__return_data = 'error: ' + e.__str__()
