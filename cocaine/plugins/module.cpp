/*
 * Copyright 2013+ Ruslan Nigmatullin <euroelessar@yandex.ru>
 * Copyright 2011-2012 Andrey Sibiryov <me@kobology.ru>
 *
 * This file is part of Elliptics.
 *
 * Elliptics is free software: you can redistribute it and/or modify
 * it under the terms of the GNU Lesser General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 *
 * Elliptics is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU Lesser General Public License for more details.
 *
 * You should have received a copy of the GNU Lesser General Public License
 * along with Elliptics.  If not, see <http://www.gnu.org/licenses/>.
 */


#include "storage.hpp"
#include "service.hpp"

using namespace cocaine;
using namespace cocaine::storage;

extern "C" {

void initialize(api::repository_t& repository) {
	repository.insert<elliptics_storage_t>("elliptics");
	repository.insert<elliptics_service_t>("elliptics");
}

}

