d = {'script' : 'read_latest', 'dentry_name' : pohmelfs_dentry_name}

try:
	binary_data = __input_binary_data_tuple[0]

	if len(binary_data) < 88:
		raise NameError('Invalid binary size: ' + str(len(binary_data)))

	group_id, type, offset, size = struct.unpack("<iiQQ", str(binary_data[64:]))

	id = elliptics_id(list(binary_data[0:64]), group_id, type)
	d['object'] = dump_id(id)

	__return_data = n.prepare_latest_str(id, pohmelfs_aflags, pohmelfs_groups)
	logging.error("read latest", extra=d)

	gc.collect()

except KeyError as e:
	logging.error("key error: %s", e.__str__(), extra=d)
	# returning empty __return_data ends up sending only ack message to client
	# we do not support exception/error propagation to caller
	# so we need something to show that there was an error
	# particular caller does not 'accept' strings less than 4 bytes,
	# so this will be an error
	__return_data = '-'
except Exception as e:
	logging.error("generic error: %s", e.__str__(), extra=d)
	__return_data = '-'
