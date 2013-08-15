#!/usr/bin/python

import elliptics
from elliptics_recovery.route import RouteList, Address
from elliptics_recovery.range import IdRange
from elliptics_recovery.etime import Time

def iterate_node(range):
    pass

if __name__ == '__main__':
    from optparse import OptionParser
    parser = OptionParser()
    parser.usage = "%prog [options] TYPE"
    parser.description = __doc__
    parser.add_option("-r", "--remote", action="store", dest="elliptics_remote", default=None,
                      help="Elliptics node address [default: %default]")

    (options, args) = parser.parse_args()

    elog = elliptics.Logger('/var/tmp/iterate.log', 1)
    cfg = elliptics.Config()
    cfg.config.wait_timeout = 3600
    cfg.config.check_timeout = 30
    node = elliptics.Node(elog, cfg)
    address = None
    if options.elliptics_remote is None:
        raise ValueError("Recovery address should be given (-r option).")
    try:
        address = Address.from_host_port_family(options.elliptics_remote)
    except Exception as e:
        raise ValueError("Can't parse host:port:family: '{0}': {1}".format(options.elliptics_remote,
                                                                           repr(e)))
    node.add_remote(addr=address.host, port=address.port, family=address.family)
    session = elliptics.Session(node)
    routes = RouteList.from_session(session)
    session.groups = [1]

    ranges = [IdRange.elliptics_range(start, stop) for start, stop in (IdRange(IdRange.ID_MIN, IdRange.ID_MAX),)]
    records = session.start_iterator(routes.get_address_eid(address),
                                     ranges,
                                     elliptics.iterator_types.network,
                                     elliptics.iterator_flags.key_range,
                                     Time.time_min().to_etime(),
                                     Time.time_max().to_etime())

    total_records = 0

    for record in records:
        if record.status != 0:
            raise RuntimeError("Iteration status check failed: {0}".format(record.status))
        total_records += 1

    all_ranges = routes.get_local_ranges_by_address(address)
    local_ranges = next((r for r in all_ranges if r.address == address), None)
    ranges = [IdRange.elliptics_range(start, stop) for start, stop in local_ranges.id_ranges]
    records = session.start_iterator(routes.get_address_eid(address),
                                     ranges,
                                     elliptics.iterator_types.network,
                                     elliptics.iterator_flags.key_range,
                                     Time.time_min().to_etime(),
                                     Time.time_max().to_etime())

    legal_records = 0

    for record in records:
        if record.status != 0:
            raise RuntimeError("Iteration status check failed: {0}".format(record.status))
        legal_records += 1

    print "Node {0} has {1} legal records and {2} hidden records. Total records: {3}".format(address, legal_records, total_records - legal_records, total_records)
