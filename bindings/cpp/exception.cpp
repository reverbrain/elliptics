/*
 * 2008+ Copyright (c) Evgeniy Polyakov <zbr@ioremap.net>
 * 2012+ Copyright (c) Ruslan Nigmatullin <euroelessar@yandex.ru>
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

#include <elliptics/cppdef.h>

using namespace ioremap::elliptics;

elliptics_error::elliptics_error(int code)
    : std::runtime_error(convert(code)), errno_(code)
{
}

int elliptics_error::error_code() const
{
    return errno_;
}

std::string elliptics_error::convert(int err)
{
    return strerror(err);
}

not_found_error::not_found_error()
    : elliptics_error(ENOENT)
{
}

timeout_error::timeout_error()
    : elliptics_error(EIO)
{
}

void throw_exception(int err)
{
    throw elliptics_error(err);
}
