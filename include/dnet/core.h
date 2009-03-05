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

#include "dnet/typedefs.h"

#define EL_HISTORY_SUFFIX	".history"

#define __unused		__attribute__ ((unused))

#define EL_ID_SIZE		20		/* Has to match selected hash type */
#define EL_MAX_NAME_LEN		64

/*
 * Each read transaction reply is being split into
 * chunks of this bytes max, thus reading transaction
 * callback will be invoked multiple times.
 */
#define MAX_READ_TRANS_SIZE	(1024*1024*10)

#define DNET_TIMEOUT		5000

#endif /* __DNET_CORE_H */
