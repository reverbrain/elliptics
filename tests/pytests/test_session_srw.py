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
from conftest import raises, make_trace_id
import elliptics

EVENT = 'dnet_cpp_srw_test_app@info'


@pytest.mark.skipif(pytest.config.option.without_cocaine,
                    reason="COCAINE wasn't specified")
class TestSession:
    # Test on Session.exec_ usage variants (arg values).
    #
    @pytest.mark.skipif(pytest.config.option.without_cocaine,
                        reason="COCAINE wasn't specified")
    def test_exec_arg_event_cant_be_none(self, elliptics_client, elliptics_groups, server):
        elliptics_client.trace_id = make_trace_id('TestSession.test_exec_arg_event_cant_be_none')
        with pytest.raises(TypeError):
            elliptics_client.exec_('some-id', data='')

    @pytest.mark.skipif(pytest.config.option.without_cocaine,
                        reason="COCAINE wasn't specified")
    def test_exec_arg_event_cant_be_missed(self, elliptics_client, elliptics_groups, server):
        elliptics_client.trace_id = make_trace_id('TestSession.test_exec_arg_event_cant_be_missed')
        with pytest.raises(TypeError):
            elliptics_client.exec_('some-id', event=None, data='')

    @pytest.mark.skipif(pytest.config.option.without_cocaine,
                        reason="COCAINE wasn't specified")
    def test_exec_arg_data_could_be_missed(self, elliptics_client, elliptics_groups, server):
        elliptics_client.trace_id = make_trace_id('TestSession.test_exec_arg_data_could_be_missed')
        r = elliptics_client.exec_('some-id', event=EVENT).get()
        assert isinstance(r, list) and len(r) == len(elliptics_groups)

    @pytest.mark.skipif(pytest.config.option.without_cocaine,
                        reason="COCAINE wasn't specified")
    def test_exec_arg_data_could_be_none(self, elliptics_client, elliptics_groups, server):
        elliptics_client.trace_id = make_trace_id('TestSession.test_exec_arg_data_could_be_none')
        r = elliptics_client.exec_('some-id', event=EVENT, data=None).get()
        assert isinstance(r, list) and len(r) == len(elliptics_groups)

    @pytest.mark.skipif(pytest.config.option.without_cocaine,
                        reason="COCAINE wasn't specified")
    def test_exec_arg_id_could_be_none(self, elliptics_client, elliptics_groups, server):
        elliptics_client.trace_id = make_trace_id('TestSession.test_exec_arg_id_could_be_none')
        nodes = elliptics_client.routes.addresses()
        r = elliptics_client.exec_(None, event=EVENT, data='').get()
        assert isinstance(r, list) and len(r) == len(nodes)

    # Different styles of using Session.exec_.
    #
    def exec_sync(self, elliptics_client, key, event, data=None):
        ''' Strictly synchronous request '''
        elliptics_client.trace_id = make_trace_id('TestSession.exec_sync')
        async = elliptics_client.exec_(key, event=event, data=data)
        # wait() call not required here but its explicit (and so is better)
        async.wait()
        return async.get(), async.error()

    def exec_async_i(self, elliptics_client, key, event, data=None):
        ''' Async request using result iterator '''
        elliptics_client.trace_id = make_trace_id('TestSession.exec_async_i')
        async = elliptics_client.exec_(key, event=event, data=data)
        return list(async), async.error()

    def exec_async_cb(self, elliptics_client, key, event, data=None):
        ''' Async request using explicit callbacks '''
        results = []
        error = []
        elliptics_client.trace_id = make_trace_id('TestSession.exec_async_cb')
        async = elliptics_client.exec_(key, event=event, data=data)
        async.connect(
            lambda x: results.append(x),
            lambda x: error.append(x)
        )
        async.wait()
        #print '%r, %r' % (results, error)
        assert len(error) > 0
        return results, error[0]

    # exec_func helps parameterize tests with different styles of using Session.exec_
    @pytest.fixture(scope='function', params=[exec_sync, exec_async_i, exec_async_cb])
    def exec_func(self, request):
        return request.param

    # Test exec styles, effect and results.
    #
    def print_result(self, r):
        print '\n'
        print 'result.address %r' % (r.address)
        for k in [i for i in dir(r.context) if i[0] != '_']:
            print 'result.context.%s = %r' % (k, getattr(r.context, k))

    def print_error(self, error):
        print '\nerror: code %r, msg %r' % (error.code, error.message)

    @pytest.mark.skipif(pytest.config.option.without_cocaine,
                        reason="COCAINE wasn't specified")
    def test_exec_styles(self, elliptics_client, elliptics_groups, exec_func, server):
        elliptics_client.trace_id = make_trace_id('TestSession.test_exec_styles')
        results, error = exec_func(self, elliptics_client, 'some-id', event=EVENT)
        assert error.code == 0
        assert len(results) == len(elliptics_groups)

    # Test content of returning ExecContexts.
    # Using (and also testing) two different fan out implementations.
    #
    @pytest.mark.skipif(pytest.config.option.without_cocaine,
                        reason="COCAINE wasn't specified")
    def test_exec_fanout_auto(self, elliptics_client, elliptics_groups, exec_func, server):
        ''' Fan out using None as id '''
        elliptics_client.trace_id = make_trace_id('TestSession.test_exec_fanout_auto')
        nodes = elliptics_client.routes.addresses()

        results, error = exec_func(self, elliptics_client, None, event=EVENT)
        for i in results:
            self.print_result(i)
        self.print_error(error)

        assert error.code == 0
        assert len(results) == len(nodes)

        for r in results:
            assert r.context.address
            assert r.address == r.context.address

            #TODO: check if src_id isn't empty
            #assert r.context.src_id.id != [0] * 64

    @pytest.mark.skipif(pytest.config.option.without_cocaine,
                        reason="COCAINE wasn't specified")
    def test_exec_fanout_manual(self, elliptics_client, elliptics_groups, exec_func, server):
        ''' Fan out using manual lookup into routing table '''
        elliptics_client.trace_id = make_trace_id('TestSession.test_exec_fanout_manual')
        nodes = elliptics_client.routes.get_unique_routes()

        collected = []
        for route in nodes:
            print '\nFor addr %s, key %r:' % (route.address, route.id)
            results, error = exec_func(self, elliptics_client, route.id, event=EVENT)
            for i in results:
                self.print_result(i)
            self.print_error(error)

            assert error.code == 0
            assert len(results) == 1

            collected.append((route.address, route.id, results[0]))

        for route.address, route.id, r in collected:
            assert r.context.address
            assert r.address == r.context.address

            #TODO: check if src_id isn't empty
            #assert r.context.src_id == id

    @pytest.mark.skipif(pytest.config.option.without_cocaine,
                        reason="COCAINE wasn't specified")
    def test_exec_arg_event_could_be_positional(self, elliptics_client, elliptics_groups, server):
        elliptics_client.trace_id = make_trace_id('TestSession.test_exec_arg_event_could_be_positional')
        r = elliptics_client.exec_('some-id', EVENT, data=None).get()
        assert isinstance(r, list) and len(r) == len(elliptics_groups)
