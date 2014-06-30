/*
 * Copyright 2013+ Evgeniy Polyakov <zbr@ioremap.net>
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *    http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

#ifndef __IOREMAP_TIMER_HPP
#define __IOREMAP_TIMER_HPP

#include <chrono>

namespace ioremap { namespace elliptics {

class timer
{
	typedef std::chrono::high_resolution_clock clock;
public:
	timer() : m_last_time(clock::now())
	{
	}

	int64_t elapsed() const
	{
		int64_t t = std::chrono::duration_cast<std::chrono::milliseconds>(clock::now() - m_last_time).count();
		if (!t)
			t = 1;

		return t;
	}

	int64_t restart()
	{
		clock::time_point time = clock::now();
		std::swap(m_last_time, time);
		int64_t t = std::chrono::duration_cast<std::chrono::milliseconds>(m_last_time - time).count();
		if (!t)
			t = 1;

		return t;
	}

private:
	clock::time_point m_last_time;
};


}} // namespace ioremap::elliptics

#endif /* __IOREMAP_TIMER_HPP */
