# =============================================================================
# 2013+ Copyright (c) Kirill Smorodinnikov <shaitkir@gmail.com>
# All rights reserved.
#
# This program is free software; you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation; either version 2 of the License, or
# (at your option) any later version.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
# =============================================================================

from elliptics.core import Session
from elliptics.route import RouteList, Address
from elliptics.log import logged_class


@logged_class
class Session(Session):
    def __init__(self, node):
        '''
        Initializes session by the node"

        session = elliptics.Session(node)"
        '''
        super(Session, self).__init__(node)
        self._node = node

    def clone(self):
        '''
        Creates and returns session which is equal to current"
        but complitely independent from it."

        cloned_session = session.clone()
        '''
        session = super(Session, self).clone()
        session._node = self._node
        return session

    @property
    def routes(self):
        """
        Returns current routes table\n
        routes = session.routes
        """
        return self.get_routes()

    def get_routes(self):
        """
        Returns current routes table\n
        routes = session.get_routes
        """
        return RouteList.from_routes(super(Session, self).get_routes())

    def lookup_address(self, key, group_id):
        """
        Returns address of node from specified group_id which is responsible for the key\n
        address = session.lookup_address('looking up key')
        print '\'looking up key\' should lives on node:', address
        """
        return Address.from_host_port(super(Session, self)
                                      .lookup_address(key, group_id), group_id)

    def set_indexes(self, id, indexes, datas=None):
        """
        set_indexes(id, indexes, datas=None)
        Resets id indexes. The id will be removed from previous indexes.
        Also it updates list of indexes where id is.
        Returns elliptics.AsyncResult.
        -- id - string or elliptics.Id
        -- indexes - iterable object which provides set of indexes or dict of {'index':'data'}
        -- datas - iterable object which provides data which will be associated with the id in the index.\n
        indexes_result = []
        try:
            result = session.set_indexes('key', ['index1', 'index2'], ['index1_key_data', 'index2_key_data'])
            indexes_result = result.get()
        except Exception as e:
            print 'Set indexes has been failed:', e\n
        try:
            result = session.set_indexes('key', {'index1':'index1_key_data',
                                                 'index2':'index2_key_data'})
            indexes_result = result.get()
        except Exception as e:
            print 'Set indexes has been failed:', e
        """
        if type(indexes) is dict:
            datas = indexes.values()
            indexes = indexes.keys()

        return super(Session, self).set_indexes(id, indexes, datas)

    def update_indexes(self, id, indexes, datas=None):
        """
        Adds id to additional indees and or updates data for the id in specified indexes.
        Also it updates list of indexes where id is.
        Return elliptics.AsyncResult.
        -- id - string or elliptics.Id
        -- indexes - iterable object which provides set of indexes or dict of {'index':'data'}
        -- datas - iterable object which provides data which will be associated with the id in the index.\n
        indexes_result = []
        try:
            result = session.update_indexes('key', ['index3', 'index4'],
                                            ['index3_key_data', 'index4_key_data'])
            indexes_result = result.get()
        except Exception as e:
            print 'Update indexes has been failed:', e\n
        try:
            result = session.update_indexes('key', {'index3':'index3_key_data',
                                                    'index4':'index4_key_data'})
            indexes_result = result.get()
        except Exception as e:
            print 'Update indexes has been failed:', e
        """
        if type(indexes) is dict:
            datas = indexes.values()
            indexes = indexes.keys()

        return super(Session, self).update_indexes(id, indexes, datas)

    def update_indexes_internal(self, id, indexes, datas=None):
        """
        Adds id to additional indees and or updates data for the id in specified indexes.
        It doesn't update list of indexes where id is.
        Return elliptics.AsyncResult.
        -- id - string or elliptics.Id
        -- indexes - iterable object which provides set of indexes
        -- datas - iterable object which provides data which will be associated with the id in the index.\n
        indexes_result = []
        try:
            result = session.update_indexes_internal('key', ['index5', 'index6'],
                                                     ['index5_key_data', 'index6_key_data'])
            indexes_result = result.get()
        except Exception as e:
            print 'Update indexes has been failed:', e\n
        indexes_result = []
        try:
            result = session.update_indexes_internal('key', {'index5':'index5_key_data',
                                                             'index6':'index6_key_data'})
            indexes_result = result.get()
        except Exception as e:
            print 'Update indexes internal has been failed:', e
        """
        if type(indexes) is dict:
            datas = indexes.values()
            indexes = indexes.keys()

        return super(Session, self).update_indexes_internal(id, indexes, datas)
