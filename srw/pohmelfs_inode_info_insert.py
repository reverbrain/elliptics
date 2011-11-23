offset = 0
size = 0
# do not check csum
ioflags_read = 256
ioflags_write = 0
# do not lock operation, since we are 'inside' DNET_CMD_EXEC command already
aflags = 16
column = 0
group_id = 0

import traceback

d = {'script' : 'insert', 'dentry_name' : pohmelfs_dentry_name}

try:
	binary_data = __input_binary_data_tuple[0]
	parent_id = elliptics_id(list(binary_data[0:64]), group_id, column)
	inode_info = str(binary_data[64:])

	s = sstable()
	try:
		dir_content = n.read_data(parent_id, offset, size, aflags, ioflags_read)
		s.load(dir_content)
	except Exception as e:
		logging.info("read data 1: %s", e.__str__(), extra=d)
		s.init(256 + len(inode_info) + 8)

	s.insert(pohmelfs_dentry_name, inode_info, True)
	content = str(s.save())

	n.write_data(parent_id, content, offset, aflags, ioflags_write)
	n.write_metadata(parent_id, '', pohmelfs_groups)
	logging.info("inserted", extra=d)
	__return_data = 'ok'
except KeyError as e:
	logging.error("key error: %s", e.__str__(), extra=d)
	__return_data = 'key error: ' + e.__str__()
except Exception as e:
	logging.error("generic error: %s", e.__str__(), extra=d)
	__return_data = 'error: ' + e.__str__()
