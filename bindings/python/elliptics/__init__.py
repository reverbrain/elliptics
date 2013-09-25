from __future__ import absolute_import

from elliptics.core import *
import elliptics.route
import elliptics.session
from elliptics.route import *
from elliptics.session import *
from elliptics.node import *


@property
def storage_address(self):
    return Address.from_host_port(self.__storage_address__)

LookupResultEntry.__storage_address__ = LookupResultEntry.storage_address
LookupResultEntry.storage_address = storage_address

del elliptics.route
del elliptics.session
