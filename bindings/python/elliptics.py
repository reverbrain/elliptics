#!/usr/bin/python
# -*- coding: utf-8 -*-
import hashlib
import binascii
import struct

import libelliptics_python
from libelliptics_python import log_level, command_flags, io_flags


class NodeStatus(libelliptics_python.dnet_node_status):
    def __repr__(self):
        return "<NodeStatus nflags:%x, status_flags:%x, log_mask:%x>" % (self.nflags, self.status_flags, self.log_mask)


class Id(libelliptics_python.elliptics_id):
    """
     Elliptics ID wrapper
     It has 2 constructors:
         Id()
         Id(list_id, group type)

     list_id - list of 64 bytes, id of the object itself
     group - group ID of the object
     type - column
    """
    pass


class Range(libelliptics_python.elliptics_range):
    """
     Structure that describes range request
     start, end - IDs of the start and the end of the range
     offset, size - offset to read from and size of bytes to read, applied for each key
     cflags - command flags like locking so on (default is 0, see cflags class for defenitions)
     ioflags - command IO flags (default is 0, see ioflags class for definitions)
     group - group ID of the object
     type - column
    """
    pass


class Logger(libelliptics_python.elliptics_log_file):
    """
     Logger, that needed in Node constructor
     Constructor takes 2 arguments: log file name (default is "/dev/stderr")
     and log level (default is log_level.error, see log_level class for definitions)
    """
    log_file_name = ""
    llevel = log_level.error

    def __init__(self, log_file_name = "/dev/stderr", llevel = log_level.error):
        """
          log_file_name - name of the log file, default value is "/dev/stderr"
          log_level - logging level, see log_level class for definitions
        """
        self.log_file_name = log_file_name
        self.llevel = llevel
        super(Logger, self).__init__(log_file_name, llevel)

    def log(self, message, level):
        """
          log some message into elliptics log file
          message - text message
          level - log level, default is log_level.error (see log_level class for definitions)
        """
        super(Logger, self).log(level, message)

    def __repr__(self):
        return "<Logger log_file_name:\"%s\" log_level:%d>" % (self.log_file_name, self.llevel)


class Node(libelliptics_python.elliptics_node_python):
    """
     Main client class. Constructor takes 1 argument: Logger object
     """

    def __init__(self, log=None):
        """
          log - Logger object
        """
        super(Node, self).__init__(log or Logger())

    def add_remote(self, addr, port, family=2):
        """
          Add address of elliptics storage node and connect to it
	  Usually you do not want to exit if client failed to connect to remote node, so catch up exceptions
	  But if no remote nodes were successfully added (check get_routes()) then client should not continue
          addr - storage address
          port - storage port
          family - IP protocol family: 2 for IPv4 (default value) and 10 for IPv6
        """
        super(Node, self).add_remote(addr, port, family)

    def add_groups(self, groups):
        """
          Set groups to work with
          groups - list of groups
        """
        super(Node, self).add_groups(groups)

    @property
    def groups(self):
        return super(Node, self).get_groups()

    def get_routes(self):
        """
          Get routing table

          return value:
          list - list of node addresses
        """
        return super(Node, self).get_routes()

    def stat_log(self):
        """
          Get nodes statistics

          return value:
          string - storage nodes statistics
        """
        return super(Node, self).stat_log()

    def lookup_addr(self, *args, **kwargs):
        """
          Lookup where key should be located by its ID or key and group_id pair
          signatures:
              lookup_addr(key, group_id)
              lookup_addr(id)

          key - remote key name
          group_id - group
          id - object of Id class

          return value:
          string - node address
        """
        return super(Node, self).lookup_addr(*args, **{})

    def read_file(self, key, filename, offset = 0, size = 0, column = 0):
        """
          Read file from elliptics by name/ID
          signatures:
              read_file(key, filename, offset, size, column)
              read_file(id, filename, offset, size)

          key - remote key name
          column - column type (default is 0, 1 is reserved for metadata)
          id - object of Id class

          filename - name of local file where data will be saved
          offset - read file from this offset (default 0)
          size - number of bytes to read, 0 means whole file (default is 0)
        """
        if isinstance(key, basestring):
            new_args = [str(key), filename, offset, size, column]
        else:
            new_args = [key, filename, offset, size]

        super(Node, self).read_file(*new_args)

    def write_file(self, key, filename, local_offset = 0, offset = 0, size = 0, \
		    cflags = command_flags.default, ioflags = io_flags.default, column = 0):
        """
          Write file into elliptics by name/ID
          signatures:
              write_file(key, filename, local_offset, offset, size, cflags, ioflags, column)
              write_file(id, filename, local_offset, offset, size, cflags, ioflags)

          key - remote key name
          column - column type (default is 0, 1 is reserved for metadata)
          id - object of Id class

          filename - name of local file
          local_offset - read local file from this offset (default 0)
          offset - write file from this offset (default 0)
          size - number of bytes to write, 0 means whole file (default is 0)
          cflags - command flags (default is 0, see command_flags class for definitions)
          ioflags - command IO flags (default is 0, see io_flags class for definitions)
        """
        if isinstance(key, basestring):
            new_args = [str(key), filename, local_offset, offset, size, cflags, ioflags, column]
        else:
            new_args = [key, filename, local_offset, offset, size, cflags, ioflags]

        super(Node, self).read_file(*new_args)

    def _create_read_args(self, key, offset = 0, size = 0, cflags = command_flags.default, ioflags = io_flags.default, column = 0):
        if isinstance(key, basestring):
            return [str(key), offset, size, cflags, ioflags, column]
        else:
            return [key, offset, size, cflags, ioflags]

    def read_data(self, key, offset = 0, size = 0, cflags = command_flags.default, ioflags = io_flags.default, column = 0):
        """
          Read data from elliptics by name/ID
          signatures:
              read_data(key, offset, size, cflags, ioflags, column)
              read_data(id, offset, size, cflags, ioflags)

          key - remote key name
          column - column type (default is 0, 1 is reserved for metadata)
          id - object of Id class

          offset - read file from this offset (default 0)
          size - number of bytes to read, 0 means whole file (default is 0)
          cflags - command flags (default is 0, see command_flags class for definitions)
          ioflags - command IO flags (default is 0, see io_flags class for definitions)

          return value:
          string - key value content
        """
        return super(Node, self).read_data(*self._create_read_args(key, offset, size, cflags, ioflags, column))

    read = read_data

    def read_latest(self, key, offset = 0, size = 0, cflags = command_flags.default, ioflags = io_flags.default, column = 0):
        """
          Read data from elliptics by name/ID with the latest update_date in metadata
          signatures:
              read_latest(key, offset, size, cflags, ioflags, column)
              read_latest(id, offset, size, cflags, ioflags)

          key - remote key name
          column - column type (default is 0, 1 is reserved for metadata)
          id - object of Id class

          offset - read file from this offset (default 0)
          size - number of bytes to read, 0 means whole file (default is 0)
          cflags - command flags flags (default is 0, see command_flags class for definitions)
          ioflags - command IO flags (default is 0, see io_flags class for definitions)

          return value:
          string - key value content
        """
        return super(Node, self).read_latest(*self._create_read_args(key, offset, size, cflags, ioflags, column))

    def create_write_args(self, key, data, offset, ioflags, cflags, column):
        if isinstance(key, basestring):
            return [str(key), data, offset, cflags, ioflags, column]
        else:
            return [key, data, offset, cflags, ioflags]

    def write_data(self, key, data, offset = 0, cflags = command_flags.default, ioflags = io_flags.default, column = 0):
        """
         Write data into elliptics by name/ID
         signatures:
             write_data(key, data, offset, cflags, ioflags, column)
             write_data(id, data, offset, cflags, ioflags)

         key - remote key name
         column - column type (default is 0, 1 is reserved for metadata)
         id - object of Id class

         data - data to be written
         offset - write data in remote from this offset (default 0)
         cflags - command flags flags (default is 0, see command_flags class for definitions)
         ioflags - command IO flags (default is 0, see io_flags class for definitions)

         return value:
         string - nodes and paths where data was stored
         """
        return super(Node, self).write_data(*self.create_write_args(key, data, offset, ioflags, cflags, column))

    def write_metadata(self, key, cflags = command_flags.default, name = None, groups = None):
        """
         Write metadata into elliptics by name/ID
         signatures:
             write_metadata(key, cflags)
             write_metadata(id, name, groups, cflags)

         key - remote key name
         id - object of Id class

         name - key name
         groups - groups where data was stored
         cflags - command flags (default is 0, see command_flags class for definitions)
        """
        if isinstance(key, basestring):
            new_args = [str(key), cflags]
        else:
            new_args = [key, name, groups, cflags]

        super(Node, self).write_metadata(*new_args)

    def write(self, key, data):
        """
        Simple write
        """
        self.write_data(key, data)
        self.write_metadata(key)

    def remove(self, key, cflags = command_flags.default, ioflags = io_flags.default, column = 0):
        """
             Remove key by name/ID
             signatures:
                 remove(key, cflags, ioflags, column)
                 remove(id, cflags, ioflags)

             key - remote key name
             column - column type (default is 0, 1 is reserved for metadata)
             id - object of Id class

             cflags - command flags flags (default is 0, see command_flags class for definitions)
             ioflags - command IO flags (default is 0, see io_flags class for definitions)
        """
        if isinstance(key, basestring):
            new_args = [str(key), cflags, ioflags, column]
        else:
            new_args = [key, cflags, ioflags]

        super(Node, self).remove(*new_args)

    def execute(self, *args, **kwargs):
        """
             Execite server-side script
             signatures:
                 exec(id, event, data, binary)
                 exec(key, event, data, binary)
                 exec(event, data, binary)

             key - remote key name
             id - object of Id class

             event - server-side event name
	     data - data for given event
             binary - binary data (its logical meaning is the same as for data, it was added for convenience)

             If execute() is called with 3 arguments script will be started on all storage nodes.
             If id or key is specified script will be started on the node which hosts given key/id.

             return value:
             string - result of the script execution
        """
        return super(Node, self).execute(*args, **{})

    def update_status(self, key, status = None, update = 0):
        """
             Update elliptics status and log mask
             signatures:
                 update_status(id, status, update)
                 update_status((addr, port, family), status, update)

             key - remote key name
             id - object of Id class

             addr - storage address
             port - storage port
             family - IP protocol family: 2 for IPv4 (default value) and 10 for IPv6
             status - new node status, object of NodeStatus class
             update - update status or just return current (default is 0)

             If update = 0 status will not be changed

             return value:
             NodeStatus - current node status
        """
        status = status or NodeStatus()
        if hasattr(key, '__iter__'):
            new_args = (key[0], key[1], key[2], status, update)
        else:
            new_args = (key, status, update)

        ret = super(Node, self).update_status(*new_args)
        ret.__class__ = NodeStatus
        return ret

    def bulk_read(self, keys, cflags = command_flags.default, raw=False):
        """
         Bulk read keys from elliptics
         keys - list of keys by name
         cflags - command flags (default is 0, see command_flags class for definitions)

         return value:
         dict: key - original key, value - data itself
         if raw is True: list - list of strings, each string consists of 64 byte key (sha-512 of original key), 8 byte data length and data itself
        """
        if type(keys) in set([tuple, list, set, dict]):
            keys = list(keys)

        rv = super(Node, self).bulk_read(keys, cflags)

        if raw:
            return rv

        if not rv:
            return {}

        keys = dict([(hashlib.sha512(key).hexdigest(), key) for key in keys])

        rv_dict = {}
        for r in rv:
            key = binascii.hexlify(r[:64])
            data_len = struct.unpack('Q', r[64:72])[0]
            data = struct.unpack("%ss" % data_len, r[72:72 + data_len])[0]
            rv_dict[keys[key]] = data
        return rv_dict



    def read_data_range(self, read_range):
        """
             Read keys from elliptics by range of IDs
             read_range - object of Range class

             return value:
             list - list of strings, each string consists of 64 byte key, 8 byte data length and data itself
        """
        return super(Node, self).read_data_range(read_range)


