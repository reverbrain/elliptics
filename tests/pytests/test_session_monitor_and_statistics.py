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
import pytest
from datetime import datetime, timedelta
from conftest import make_session

import elliptics

class MonitorStatsChecker:
    def __init__(self, address, session, categories):
        '''
        Initializes checkers and sets address (monitor statisitcs provider), session and
        categories that will be requested and checked
        '''
        self.checkers = {
            elliptics.core.monitor_stat_categories.cache            : self.__check_cache_stat,
            elliptics.core.monitor_stat_categories.io               : self.__check_io_stat,
            elliptics.core.monitor_stat_categories.commands         : self.__check_commands_stat,
            elliptics.core.monitor_stat_categories.backend          : self.__check_backend_stat,
            elliptics.core.monitor_stat_categories.procfs           : self.__check_procfs_stat}
        self.address = address
        self.session = session
        self.categories = categories

    def get_and_check(self):
        '''
        Requests monitoring statistics of @self.categories and executes all categories checkers
        '''
        self.start_time = datetime.now()
        entry = self.session.monitor_stat(self.address, categories=self.categories).get()[0]
        try:
            assert type(entry.address) is elliptics.Address
            self.json_stat = entry.statistics
        except Exception as e:
            with open("monitor.stat.json", "w") as f:
                f.write(entry.__statistics__)
            raise e

        self.end_time = datetime.now()
        self.__check_json_stat()

    @staticmethod
    def convert_timestamp(value):
        return datetime.fromtimestamp(value['tv_sec']) + timedelta(microseconds=value['tv_usec'])

    @staticmethod
    def __check_timestamp(value):
        '''checks timestamp values'''
        assert value['tv_sec'] >= 0
        assert value['tv_usec'] >= 0

    def __check_global_stat(self):
        '''checks top-level values of statistics which is common for all categories'''
        assert self.json_stat['monitor_status'] == 'enabled'
        MonitorStatsChecker.__check_timestamp(self.json_stat['timestamp'])
        assert self.json_stat['string_timestamp']
        statistics_timestamp = MonitorStatsChecker.convert_timestamp(self.json_stat['timestamp'])
        assert self.start_time < statistics_timestamp < self.end_time

    def __check_json_stat(self):
        '''
        checks common statistics for all categories.
        Determines which categories should be presented and run corresponding checkers
        '''
        assert self.json_stat
        self.__check_global_stat()

        for category, checker in self.checkers.items():
            if self.categories & category:
                checker()

    def __check_backend_json(self, backend_json, backend_id):
        '''checks common part of one backend json'''
        assert backend_json['backend_id'] == backend_id
        assert backend_json['status']['state'] == 1
        assert backend_json['status']['string_state']
        assert backend_json['status']['defrag_state'] == 0
        assert backend_json['status']['string_defrag_state']
        MonitorStatsChecker.__check_timestamp(backend_json['status']['last_start'])
        assert backend_json['status']['string_last_time']
        last_start = MonitorStatsChecker.convert_timestamp(backend_json['status']['last_start'])
        assert last_start < self.end_time
        assert backend_json['status']['last_start_err'] == 0
        assert backend_json['status']['read_only'] == False

    def __check_backends_common(self):
        '''checks common part of all backends and checks that all backends are presented in json'''
        node_backends = self.session.routes.get_address_backends(self.address)
        assert len(self.json_stat['backends']) == len(node_backends) == len(set(node_backends))
        for backend_id in node_backends:
            self.__check_backend_json(self.json_stat['backends'][str(backend_id)], backend_id)

    def __check_cache_stat(self):
        '''full check of cache statistics in json'''
        self.__check_backends_common()
        def check_counters(cache_json):
            assert cache_json['size'] >= 0
            assert cache_json['removing_size'] == 0
            assert cache_json['objects'] >= 0
            assert cache_json['removing_objects'] == 0
            assert len(cache_json['pages_sizes']) == 1
            assert len(cache_json['pages_max_sizes']) == 1
            for i, value in enumerate(cache_json['pages_sizes']):
                assert 0 <= value <= cache_json['pages_max_sizes'][i]

        for backend_id in self.json_stat['backends']:
            cache_json = self.json_stat['backends'][backend_id]['cache']
            check_counters(cache_json['total_cache']['size_stats'])
            assert len(cache_json['caches']) == 16
            for cache_id in cache_json['caches']:
                check_counters(cache_json['caches'][cache_id])

    def __check_io_stat(self):
        '''full check of io statistics in json'''
        self.__check_backends_common()
        def check_queue(queue_json):
            '''checks queue statistics'''
            assert queue_json['current_size'] >= 0
        io = self.json_stat['io']
        check_queue(io['blocking'])
        check_queue(io['nonblocking'])
        check_queue(io['output'])
        assert io['blocked'] == False

        for state in io['states']:
            state_io = io['states'][state]
            assert state_io['send_queue_size'] >= 0
            assert state_io['la'] >= 0
            assert state_io['free'] >= 0
            assert state_io['weight'] >= 0
            assert state_io['stall'] >= 0
            assert state_io['join_state'] >= 0

        for backend_id in self.json_stat['backends']:
            io = self.json_stat['backends'][backend_id]['io']
            check_queue(io['blocking'])
            check_queue(io['nonblocking'])

    def __check_commands_stat(self):
        '''full check of commands statistics in json'''
        commands = self.json_stat['commands']
        def check_counters(json, check_counters, check_time_and_size):
            '''checks counters, time and size of command counters'''
            if check_counters:
                assert json['successes'] >= 0
                assert json['failures'] >= 0
            if check_time_and_size:
                assert json['size'] >= 0
                assert json['time'] >= 0

        def check_command(json):
            '''checks different command counters'''
            check_counters(json['cache']['outside'], check_counters=True, check_time_and_size=True)
            check_counters(json['cache']['internal'], check_counters=True, check_time_and_size=True)
            check_counters(json['disk']['outside'], check_counters=True, check_time_and_size=True)
            check_counters(json['disk']['internal'], check_counters=True, check_time_and_size=True)

            check_counters(json['total']['storage'], check_counters=True, check_time_and_size=False)
            check_counters(json['total']['proxy'], check_counters=True, check_time_and_size=False)

        for command in commands:
            if command == 'clients':
                clients = commands[command]
                for client in clients:
                    client_commands = clients[client]
                    for command in client_commands:
                        check_counters(client_commands[command], check_counters=True, check_time_and_size=False)
            else:
                check_command(commands[command])

    def __check_io_histograms_stat(self):
        '''full check of io histograms statistics in json'''
        def check_column(json):
            '''checks one column of histograms'''
            assert json["<500 usecs"] >= 0
            assert json["<5000 usecs"] >= 0
            assert json["<100000 usecs"] >= 0
            assert json[">100000 usecs"] >= 0

        def check_one_snapshot(snapshot):
            '''splits snapshot on collumns and checks it.'''
            check_column(snapshot["<100 bytes"])
            check_column(snapshot["<500 bytes"])
            check_column(snapshot["<1000 bytes"])
            check_column(snapshot[">1000 bytes"])

        def check_snapshots(json):
            '''checks all snapshots'''
            check_one_snapshot(json['last_snapshot'])
            for snapshot in json['snapshots']:
                check_one_snapshot(snapshot)

        def check_histogram(json):
            '''checks different histograms of command'''
            check_snapshots(json['disk'])
            check_snapshots(json['cache'])
            check_snapshots(json['disk_internal'])
            check_snapshots(json['cache_internal'])

        histograms = self.json_stat['histogram']
        check_histogram(histograms['read'])
        check_histogram(histograms['write'])
        check_histogram(histograms['indx_update'])
        check_histogram(histograms['indx_internal'])

    def __check_backend_stat(self):
        '''full check of backend statistics in json'''
        self.__check_backends_common()
        for backend_id in self.json_stat['backends']:
            backend = self.json_stat['backends'][backend_id]['backend']

            global_stats = backend['global_stats']
            assert global_stats['datasort_start_time'] >= 0
            assert global_stats['read_copy_updates'] >= 0
            assert global_stats['prepare_reused'] >= 0
            assert global_stats['memory_index_tree'] >= 0
            assert global_stats['lookup_reads_number'] >= 0
            assert global_stats['data_reads_number'] >= 0
            assert global_stats['writes_number'] >= 0
            assert global_stats['reads_size'] >= 0
            assert global_stats['writes_size'] >= 0
            assert global_stats['index_files_reads_number'] >= 0
            assert global_stats['datasort_completion_time'] >= 0
            assert global_stats['datasort_completion_status'] >= 0

            def check_base_stat(json):
                '''checks one base statistics'''
                assert json['records_total'] >= 0
                assert json['records_removed'] >= 0
                assert json['records_removed_size'] >= 0
                assert json['records_corrupted'] >= 0
                assert json['base_size'] >= 0
                assert json['memory_bloom_filter'] >= 0
                assert json['memory_index_blocks'] >= 0
                assert json['want_defrag'] >= 0
                assert json['is_sorted'] >= 0

            check_base_stat(backend['summary_stats'])

            base_stats = backend['base_stats']
            for base in base_stats:
                check_base_stat(base_stats[base])

            config = backend['config']
            assert config['blob_flags'] >= 0
            assert config['sync'] >= 0
            assert config['data']
            assert config['blob_size'] > 0
            assert config['records_in_blob'] > 0
            assert config['defrag_percentage'] >= 0
            assert config['defrag_timeout'] >= 0
            assert config['index_block_size'] > 0
            assert config['index_block_bloom_length'] > 0
            assert config['blob_size_limit'] >= 0
            assert config['defrag_time'] >= 0
            assert config['defrag_splay'] >= 0
            assert config['group'] >= 0
            assert config['group'] == self.session.routes.get_address_backend_group(self.address, int(backend_id))

            vfs = backend['vfs']
            assert vfs['bsize'] > 0
            assert vfs['frsize'] > 0
            assert vfs['blocks'] >= 0
            assert vfs['bfree'] >= 0
            assert vfs['bavail'] >= 0
            assert vfs['files'] > 0
            assert vfs['ffree'] >= 0
            assert vfs['favail'] >= 0
            assert vfs['fsid'] >= 0
            assert vfs['flag'] >= 0
            assert vfs['namemax'] > 0

            dstat = backend['dstat']
            assert dstat['read_ios'] >= 0
            assert dstat['read_merges'] >= 0
            assert dstat['read_sectors'] >= 0
            assert dstat['read_ticks'] >= 0
            assert dstat['write_ios'] >= 0
            assert dstat['write_merges'] >= 0
            assert dstat['write_sectors'] >= 0
            assert dstat['write_ticks'] >= 0
            assert dstat['in_flight'] >= 0
            assert dstat['io_ticks'] >= 0
            assert dstat['time_in_queue'] >= 0

    def __check_procfs_stat(self):
        procfs = self.json_stat['procfs']

        vm = procfs['vm']
        if vm['error'] == 0:
            assert len(vm['la']) == 3
            assert all(x >= 0 for x in vm['la'])
            assert 0 <= vm['active'] <= vm['total']
            assert 0 <= vm['inactive'] <= vm['total']
            assert 0 <= vm['free'] <= vm['total']
            assert 0 <= vm['cached'] <= vm['total']
            assert 0 <= vm['buffers'] <= vm['total']

        io = procfs['io']
        if io['error'] == 0:
            assert io['rchar'] >= 0
            assert io['wchar'] >= 0
            assert io['syscr'] >= 0
            assert io['syscw'] >= 0
            assert io['read_bytes'] >= 0
            assert io['write_bytes'] >= 0
            assert io['cancelled_write_bytes'] >= 0

        stat = procfs['stat']
        if stat['error'] == 0:
            assert stat['threads_num'] >= 1
            assert 0 <= stat['rss'] <= stat['rsslim']
            assert stat['vsize'] >= 0
            assert stat['msize'] >= 0
            assert stat['mresident'] >= 0
            assert stat['mshare'] >= 0
            assert stat['mcode'] >= 0
            assert stat['mdata'] >= 0

def categories_combination():
    '''generates different combination of elliptics.monitor_stat_categories for future use'''
    import itertools
    combinations = []
    for count in xrange(1, len(elliptics.monitor_stat_categories.values)):
        combinations += list(itertools.combinations(elliptics.monitor_stat_categories.values.values(), count))
    for i, comb in enumerate(combinations):
        categories = 0
        for category in comb:
            categories |= category
        combinations[i] = categories
    return list(set(combinations))


class TestSession:
    def test_monitor_stat(self, server, simple_node):
        '''Simply get all statistics from all nodes and check that statistics is valid dict'''
        session = make_session(node=simple_node,
                               test_name='TestSession.test_monitor_stat')
        for addr in session.routes.addresses():
            stat = session.monitor_stat(addr).get()[0]
            assert stat.error.code == 0
            assert stat.error.message == ''
            assert type(stat.statistics) == dict

    @pytest.mark.parametrize("categories", categories_combination())
    def test_monitor_categories(self, server, simple_node, categories):
        '''Requests all possible combination of categories one by one and checks statistics'''
        session = make_session(node=simple_node,
                               test_name='TestSession.test_monitor_categories')

        checker = MonitorStatsChecker(address=session.routes.addresses()[0],
                                      session=session,
                                      categories=categories)
        checker.get_and_check()
