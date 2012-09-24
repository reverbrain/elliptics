#!/usr/bin/python
# -*- coding: utf-8 -*-

import sys

sys.path.insert(0, "/usr/lib/")
sys.path.insert(0, "./bindings/python/")
import libelliptics_python


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
     cflags - command flags like locking, checksum and so on (default is 0)
     ioflags - command IO flags (default is 0)
     group - group ID of the object
     type - column
    """
    pass


class Logger(libelliptics_python.elliptics_log_file):
    """
     Logger, that needed in Node constructor
     Constructor takes 2 arguments: log file name (default is "/dev/stderr")
     and log mask (default is 40)
    """
    log_file_name = ""
    log_mask = ""

    def __init__(self, log_file_name="/dev/stderr", log_mask=40):
        """
          log_file_name - name of the log file, default value is "/dev/stderr"
          log_mask - logging mask, default value is 40. Log mask bits:
              0 - NOTICE
              1 - INFO
              2 - TRANSACTIONS
              3 - ERROR
              4 - DEBUG
              5 - DATA
        """
        self.log_file_name = log_file_name
        self.log_mask = log_mask
        super(Logger, self).__init__(log_file_name, log_mask)

    def log(self, message, mask=16):
        """
          log some message into elliptics log file
          message - text message
          mask - log mask, default is DEBUG (see __init__ docstring for log mask bits)
        """
        super(Logger, self).log(mask, message)

    def __repr__(self):
        return "<Logger log_file_name:\"%s\" log_mask:%x>" % (self.log_file_name, self.log_mask)


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

    def read_file(self, key, filename, offset=0, size=0, type_=0):
        """
          Read file from elliptics by name/ID
          signatures:
              read_file(key, filename, offset, size, type)
              read_file(id, filename, offset, size)

          key - remote key name
          type - column type (default is 0, 1 is reserved for metadata)
          id - object of Id class

          filename - name of local file where data will be saved
          offset - read file from this offset (default 0)
          size - number of bytes to read, 0 means whole file (default is 0)
        """
        if isinstance(key, basestring):
            new_args = [str(key), filename, offset, size, type_]
        else:
            new_args = [key, filename, offset, size]

        super(Node, self).read_file(*new_args)

    def write_file(self, key, filename, local_offset=0, offset=0, size=0, aflags=0, ioflags=0, type_=0):
        """
          Write file into elliptics by name/ID
          signatures:
              write_file(key, filename, local_offset, offset, size, aflags, ioflags, type)
              write_file(id, filename, local_offset, offset, size, aflags, ioflags)

          key - remote key name
          type - column type (default is 0, 1 is reserved for metadata)
          id - object of Id class

          filename - name of local file
          local_offset - read local file from this offset (default 0)
          offset - write file from this offset (default 0)
          size - number of bytes to write, 0 means whole file (default is 0)
          aflags - command attributes flags (default is 0)
          ioflags - command IO flags (default is 0)
        """
        if isinstance(key, basestring):
            new_args = [str(key), filename, local_offset, offset, size, aflags, ioflags, type_]
        else:
            new_args = [key, filename, local_offset, offset, size, aflags, ioflags]

        super(Node, self).read_file(*new_args)

    def _create_read_args(self, key, offset=0, size=0, aflags=0, ioflags=0, type_=0):
        if isinstance(key, basestring):
            return [str(key), offset, size, aflags, ioflags, type_]
        else:
            return [key, offset, size, aflags, ioflags]

    def read_data(self, key, offset=0, size=0, aflags=0, ioflags=0, type_=0):
        """
          Read data from elliptics by name/ID
          signatures:
              read_data(key, offset, size, aflags, ioflags, type)
              read_data(id, offset, size, aflags, ioflags)

          key - remote key name
          type - column type (default is 0, 1 is reserved for metadata)
          id - object of Id class

          offset - read file from this offset (default 0)
          size - number of bytes to read, 0 means whole file (default is 0)
          aflags - command attributes flags (default is 0)
          ioflags - command IO flags (default is 0)

          return value:
          string - key value content
        """
        return super(Node, self).read_data(*self._create_read_args(key, offset, size, aflags, ioflags, type_))

    read = read_data

    def read_latest(self, key, offset=0, size=0, aflags=0, ioflags=0, type_=0):
        """
          Read data from elliptics by name/ID with the latest update_date in metadata
          signatures:
              read_latest(key, offset, size, aflags, ioflags, type)
              read_latest(id, offset, size, aflags, ioflags)

          key - remote key name
          type - column type (default is 0, 1 is reserved for metadata)
          id - object of Id class

          offset - read file from this offset (default 0)
          size - number of bytes to read, 0 means whole file (default is 0)
          aflags - command attributes flags (default is 0)
          ioflags - command IO flags (default is 0)

          return value:
          string - key value content
        """
        return super(Node, self).read_latest(*self._create_read_args(key, offset, size, aflags, ioflags, type_))

    def create_write_args(self, key, data, offset, ioflags, aflags, type_):
        if isinstance(key, basestring):
            return [str(key), data, offset, aflags, ioflags, type_]
        else:
            return [key, data, offset, aflags, ioflags]

    def write_data(self, key, data, offset=0, aflags=0, ioflags=0, type_=0):
        """
         Write data into elliptics by name/ID
         signatures:
             write_data(key, data, offset, aflags, ioflags, type)
             write_data(id, data, offset, aflags, ioflags)

         key - remote key name
         type - column type (default is 0, 1 is reserved for metadata)
         id - object of Id class

         data - data to be written
         offset - write data in remote from this offset (default 0)
         aflags - command attributes flags (default is 0)
         ioflags - command IO flags (default is 0)

         return value:
         string - nodes and paths where data was stored
         """
        return super(Node, self).write_data(*self.create_write_args(key, data, offset, ioflags, aflags, type_))

    def write_metadata(self, key, aflags=0, name=None, groups=None):
        """
         Write metadata into elliptics by name/ID
         signatures:
             write_metadata(key, aflags)
             write_metadata(id, name, groups, aflags)

         key - remote key name
         id - object of Id class

         name - key name
         groups - groups where data was stored
         aflags - command attributes flags (default is 0)
        """
        if isinstance(key, basestring):
            new_args = [str(key), aflags]
        else:
            new_args = [key, name, groups, aflags]

        super(Node, self).write_metadata(*new_args)

    def write(self, key, data):
        """
        Simple write
        """
        self.write_data(key, data)
        self.write_metadata(key)

    def remove(self, key, aflags=0, ioflags=0, type_=0, ):
        """
             Remove key by name/ID
             signatures:
                 remove(key, aflags, type)
                 remove(id, aflags, ioflags)

             key - remote key name
             type - column type (default is 0, 1 is reserved for metadata)
             id - object of Id class

             aflags - command attributes flags (default is 0)
             ioflags - IO flags (like cache)
        """
        if isinstance(key, basestring):
            new_args = [str(key), aflags, type_]
        else:
            new_args = [key, aflags]

        super(Node, self).remove(*new_args)

    def execute(self, *args, **kwargs):
        """
             Execite server-side script
             signatures:
                 exec(id, script, binary, type)
                 exec(script, binary, type)
                 exec(key, script, binary, type)

             key - remote key name
             id - object of Id class

             script - server-side script
             binary - data for server-side script
             type - type of execution

             If execute() is called with 3 arguments script will be runned on all storage nodes.
             If id or key is specified script will be runned on one node according to key/id.

             return value:
             string - result of the script execution
        """
        return super(Node, self).execute(*args, **{})


    def exec_name(self, *args, **kwargs):
        """
             Execite server-side script by name
             signatures:
                 exec_name(id, name, script, binary, type)
                 exec_name(name, script, binary, type)
                 exec_name(key, name, script, binary, type)

             key - remote key name
             id - object of Id class

             name - server-side script name
             script - server-side script
             binary - data for server-side script
             type - type of execution

             If exec_name() is called with 3 arguments script will be runned on all storage nodes.
             If id or key is specified script will be runned on one node according to key/id.

             return value:
             string - result of the script execution
        """
        return super(Node, self).exec_name(*args, **{})


    def update_status(self, key, status=None, update=0):
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


    def bulk_read(self, keys, group_id, aflags=0):
        """
             Bulk read keys from elliptics
             keys - list of keys by name
             group_id - group ID
             aflags - command attributes flags (default is 0)

             return value:
             list - list of strings, each string consists of 64 byte key, 8 byte data length and data itself
        """
        return super(Node, self).bulk_read(keys, group_id, aflags)


    def read_data_range(self, read_range):
        """
             Read keys from elliptics by range of IDs
             read_range - object of Range class

             return value:
             list - list of strings, each string consists of 64 byte key, 8 byte data length and data itself
        """
        return super(Node, self).read_data_range(read_range)


