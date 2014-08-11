/*
 * Copyright 2013+ Kirill Smorodinnikov <shaitkir@gmail.com>
 * Copyright 2013+ Andrey Kashin <kashin.andrej@gmail.com>
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
 * You should have received a copy of the GNU General Public License
 * along with Elliptics.  If not, see <http://www.gnu.org/licenses/>.
 */

#ifndef REACT_STAT_PROVIDER_HPP
#define REACT_STAT_PROVIDER_HPP

#include "statistics.hpp"

#include "react/elliptics_react.hpp"

namespace ioremap { namespace monitor {

class react_stat_provider : public stat_provider {
public:
	react_stat_provider(uint32_t call_timeout);

	virtual std::string json(uint64_t categories) const;

	react::elliptics_react_aggregator_t &get_react_aggregator();

private:
	react::elliptics_react_aggregator_t	react_aggregator;
	uint32_t							m_call_timeout;
};

}} /* namespace ioremap::monitor */

#endif // REACT_STAT_PROVIDER_HPP
