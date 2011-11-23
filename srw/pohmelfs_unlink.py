offset = 0
size = 0
# do not check csum
ioflags_read = 256
ioflags_write = 0
# do not lock operation, since we are 'inside' DNET_CMD_EXEC command already
aflags = 16
column = 0
group_id = 0

d = {'script' : 'unlink', 'dentry_name' : pohmelfs_dentry_name}

try:
	binary_data = __input_binary_data_tuple[0]
	parent_id = elliptics_id(list(binary_data[0:64]), group_id, column)

	s = sstable()
	dir_content = n.read_data(parent_id, offset, size, aflags, ioflags_read)
	s.load(dir_content)

	ret = s.search(pohmelfs_dentry_name)
	if not ret:
		raise KeyError("no entry")

	payload = ret[1]
	obj_id = elliptics_id(list(bytearray(payload[0:64])), group_id, -1)

	n.remove(obj_id, aflags)

	s.delete(pohmelfs_dentry_name)
	content = str(s.save())

	n.write_data(parent_id, content, offset, aflags, ioflags_write)
	n.write_metadata(parent_id, '', pohmelfs_groups)
	__return_data = 'ok'

	logging.info("removed", extra=d)

except KeyError as e:
	logging.error("key error: %s", e.__str__(), extra=d)
	__return_data = 'key error: ' + e.__str__()
except Exception as e:
	logging.error("generic error: %s", e.__str__(), extra=d)
	__return_data = 'error: ' + e.__str__()
