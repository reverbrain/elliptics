/*
* 2013+ Copyright (c) Ruslan Nigmatullin <euroelessar@yandex.ru>
* All rights reserved.
*
* This program is free software; you can redistribute it and/or modify
* it under the terms of the GNU Lesser General Public License as published by
* the Free Software Foundation; either version 2 of the License, or
* (at your option) any later version.
*
* This program is distributed in the hope that it will be useful,
* but WITHOUT ANY WARRANTY; without even the implied warranty of
* MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
* GNU Lesser General Public License for more details.
*/

#ifndef COCAINE_FRAMEWORK_SERVICE_ELLIPTICS_STORAGE_HPP
#define COCAINE_FRAMEWORK_SERVICE_ELLIPTICS_STORAGE_HPP

#include <cocaine/messages.hpp>
#include <cocaine/framework/service.hpp>
#include <cocaine/framework/services/storage.hpp>
#include <cocaine/services/elliptics_storage.hpp>

namespace cocaine { namespace framework {

class elliptics_service_t : public storage_service_t
{
public:
	elliptics_service_t(std::shared_ptr<service_connection_t> connection) :
		storage_service_t(connection)
	{
		// pass
	}

	service_traits<io::elliptics::cache_read>::future_type
	cache_read(const std::string &collection, const std::string &key) {
		return call<io::elliptics::cache_read>(collection, key);
	}

	service_traits<io::elliptics::cache_write>::future_type
	cache_write(const std::string &collection, const std::string &key, const std::string &blob, int timeout) {
		return call<io::elliptics::cache_write>(collection, key, blob, timeout);
	}

	service_traits<io::elliptics::cache_write>::future_type
	cache_write(const std::string &collection, const std::string &key, const std::string &blob) {
		return call<io::elliptics::cache_write>(collection, key, blob);
	}

	service_traits<io::elliptics::bulk_read>::future_type
	bulk_read(const std::string &collection, const std::vector<std::string> &keys) {
		return call<io::elliptics::bulk_read>(collection, keys);
	}
};

}} // namespace cocaine::framework

#endif /* COCAINE_FRAMEWORK_SERVICE_ELLIPTICS_STORAGE_HPP */
