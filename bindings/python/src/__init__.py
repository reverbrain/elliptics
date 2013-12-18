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

from __future__ import absolute_import

from elliptics.core import ErrorInfo, trace_bit, Logger, iterator_flags
from elliptics.core import iterator_types, command_flags, io_flags, log_level
from elliptics.core import exceptions_policy, config_flags, IteratorResultContainer
from elliptics.core import Id, Time, IoAttr, status_flags, Range, IteratorRange
from elliptics.core import Error, NotFoundError, TimeoutError, filters, checkers
from elliptics.route import Address
from elliptics.session import Session
from elliptics.node import Node
from elliptics.misc import create_node
from elliptics.config import Config

__author__ = "Kirill Smorodinnikov, Evgeniy Polyakov, Ruslan Nigmatullin, Alexey Ivanov"
__copyright__ = """2008+ Copyright (c) Evgeniy Polyakov <zbr@ioremap.net>
2012+ Copyright (c) Ruslan Nigmatullin <euroelessar@yandex.ru>
2013+ Copyright (c) Kirill Smorodinnikov <shaitkir@gmail.com>
All rights reserved.

This program is free software; you can redistribute it and/or modify
it under the terms of the GNU General Public License as published by
the Free Software Foundation; either version 2 of the License, or
(at your option) any later version.

This program is distributed in the hope that it will be useful,
but WITHOUT ANY WARRANTY; without even the implied warranty of
MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
GNU General Public License for more details."""
__credits__ = ["Kirill Smorodinnikov", "Evgeniy Polyakov", "Ruslan Nigmatullin", "Alexey Ivanov"]
__license__ = "GPLv2"
__maintainer__ = "Kirill Smorodinnikov"
