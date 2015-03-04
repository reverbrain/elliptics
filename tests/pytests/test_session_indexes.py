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

import sys
sys.path.insert(0, "")  # for running from cmake
from conftest import make_session
import elliptics


class TestSession:
    def check_indexes_results(self, session, results, indexes, datas):
        import operator
        assert len(results) == len(indexes)
        res_dict = {}
        for idx in results:
            res_dict[idx.index] = idx.data
        cmp_dict = {}
        for i, idx in enumerate(indexes):
            cmp_dict[session.transform(idx)] = datas[i]
        assert sorted(res_dict.iteritems(), key=operator.itemgetter(1)) == sorted(cmp_dict.iteritems(), key=operator.itemgetter(1))

    def check_find_results(self, session, results, key, indexes, datas):
        assert len(results) == 1
        results = results[0]
        assert results.id == session.transform(key)
        self.check_indexes_results(session, results.indexes, indexes, datas)

    def check_list_indexes(self, session, key, indexes, datas):
        results = session.list_indexes(key).get()
        self.check_indexes_results(session, results, indexes, datas)

    def check_indexes(self, session, key, indexes, datas):
        any_results = session.find_any_indexes(indexes).get()
        self.check_find_results(session,
                                any_results,
                                key,
                                indexes,
                                datas)

        all_results = session.find_all_indexes(indexes).get()
        self.check_find_results(session,
                                all_results,
                                key,
                                indexes,
                                datas)

        self.check_list_indexes(session,
                                key,
                                indexes,
                                datas)

    def test_indexes_simple(self, server, simple_node):
        session = make_session(node=simple_node,
                               test_name='TestSession.test_indexes_simple')
        session.groups = session.routes.groups()

        check_dict = {}

        key = 'simple_key'
        indexes = ['simple_index_1', 'simple_index_2', 'simple_index_3', 'simple_index_4', 'simple_index_5']
        datas = ['key_data_1', 'key_data_2', 'key_data_3', 'key_data_4', 'key_data_5']
        session.set_indexes(key, indexes, datas).wait()

        for i, idx in enumerate(indexes):
            check_dict[idx] = datas[i]
        self.check_indexes(session, key, check_dict.keys(), check_dict.values())

        indexes_2 = ['simple_index_4', 'simple_index_5', 'simple_index_6', 'simple_index_7']
        datas_2 = ['key_data_4.2', 'key_data_5.2', 'key_data_6.2', 'key_data_7.2']
        session.update_indexes(key, indexes_2, datas_2).wait()

        for i, idx in enumerate(indexes_2):
            check_dict[idx] = datas_2[i]
        self.check_indexes(session, key, check_dict.keys(), check_dict.values())

        removed_indexes = indexes[:3]
        session.remove_indexes(key, removed_indexes).wait()

        for idx in removed_indexes:
            del check_dict[idx]
        self.check_indexes(session, key, check_dict.keys(), check_dict.values())

    def test_indexes_dict(self, server, simple_node):
        session = make_session(node=simple_node,
                               test_name='TestSession.test_indexes_dict')
        session.groups = session.routes.groups()

        key = 'dict_key'
        indexes = {'dict_index_1': 'key_data_1',
                   'dict_index_2': 'key_data_2',
                   'dict_index_3': 'key_data_3',
                   'dict_index_4': 'key_data_4',
                   'dict_index_5': 'key_data_5'}
        set_session = session.clone()
        # We want to count only successfully finished transactions
        set_session.set_filter(elliptics.filters.positive_final)
        result = set_session.set_indexes(key, indexes)
        assert len(result.get()) == len(session.groups)

        self.check_indexes(session, key, indexes.keys(), indexes.values())

        indexes_2 = {'dict_index_4': 'key_data_4.2',
                     'dict_index_5': 'key_data_5.2',
                     'dict_index_6': 'key_data_6.2',
                     'dict_index_7': 'key_data_7.2'}
        session.update_indexes(key, indexes_2).wait()

        indexes.update(indexes_2)
        self.check_indexes(session, key, indexes.keys(), indexes.values())
