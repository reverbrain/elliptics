/*
 * 2008+ Copyright (c) Evgeniy Polyakov <zbr@ioremap.net>
 * All rights reserved.
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 */

#ifndef __DNET_CORE_H
#define __DNET_CORE_H

#include "config.h"

#include <dnet/typedefs.h>

#define DNET_HISTORY_SUFFIX	".history"

#ifdef CONFIG_ID_SIZE
#define DNET_ID_SIZE		CONFIG_ID_SIZE
#else
#define DNET_ID_SIZE		20
#endif
#define DNET_MAX_NAME_LEN	64

#endif /* __DNET_CORE_H */
