d = {'script' : 'hardlink', 'dentry_name' : pohmelfs_dentry_name}

try:
	binary_data = __input_binary_data_tuple[0]
	obj_id = elliptics_id(list(binary_data[0:64]), pohmelfs_group_id, pohmelfs_link_number_column)

	count = 1
	try:
		count = int(n.read_data(obj_id, pohmelfs_offset, pohmelfs_size, pohmelfs_aflags, pohmelfs_ioflags_read))
		count += 1
	except:
		pass

	n.write_data(obj_id, str(count), pohmelfs_offset, pohmelfs_aflags, pohmelfs_ioflags_write)

	__return_data = 'ok'
	logging.info("created: count: %d", count, extra=d)

	gc.collect()

except KeyError as e:
	logging.error("key error: %s", e.__str__(), extra=d)
	__return_data = 'key error: ' + e.__str__()
except Exception as e:
	logging.error("generic error: %s", e.__str__(), extra=d)
	__return_data = 'error: ' + e.__str__()

