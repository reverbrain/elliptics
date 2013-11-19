/*
 * Copyright 2013+ Ruslan Nigmatullin <euroelessar@yandex.ru>
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

#ifndef FUNCTIONAL_P_H
#define FUNCTIONAL_P_H

#include <functional>
#include "callback_p.h"

#if __GNUC__ == 4 && __GNUC_MINOR__ < 5
#  include <cstdatomic>
#else
#  include <atomic>
#endif

namespace ioremap { namespace elliptics {

// Helper class for functor duties
// It's nothing more than implementation detail
//
// When usually want to use std::bind() like std::bing(&myobject::myfunction, this, args...),
// but instead we could use std::mem_fn() and store object pointer ('this') somewhere.
//
// This magic class does exactly that - it saves object pointer ('this') in given handler
// and calls requested function when operator() is invoked
template <typename Pointer, typename Func, typename ReturnType, typename... Args>
struct magic_bind_result
{
    magic_bind_result(const Pointer &pointer, Func func)
        : pointer(pointer), func(func)
    {
    }

    Pointer pointer;
    Func func;

    ReturnType operator() (Args... args)
    {
        return (*pointer.*func)(args...);
    }
};

// Creates std::function-wrapper around object method
// It was created to avoid a lot of std::placeholders::whatever at function binding
template <typename Pointer, typename Object, typename ReturnType, typename... Args>
std::function<ReturnType (Args...)> bind_method(const Pointer &pointer, ReturnType (Object::*func) (Args...))
{
    return magic_bind_result<Pointer, ReturnType (Object::*) (Args...), ReturnType, Args...>(pointer, func);
}

template <typename T>
struct aggregator_handler
{
	ELLIPTICS_DISABLE_COPY(aggregator_handler)

	aggregator_handler(const async_result<T> &result, size_t count)
		: handler(result), finished(count), has_success(false)
	{
	}

	async_result_handler<T> handler;
	std::mutex mutext;
	size_t finished;
	error_info error;
	std::atomic_bool has_success;

	void on_entry(const T &result)
	{
		if (result.status() == 0 && result.is_valid())
			has_success = true;
		handler.process(result);
	}

	void on_finished(const error_info &reply_error)
	{
		std::lock_guard<std::mutex> lock(mutext);
		if (reply_error)
			error = reply_error;
		if (--finished == 0)
			handler.complete(has_success ? error_info() : error);
	}
};

template <typename iterator>
typename iterator::value_type aggregated(session &sess, iterator begin, iterator end)
{
	typedef typename iterator::value_type async_result_type;
	typedef typename async_result_type::entry_type entry_type;
	typedef aggregator_handler<entry_type> aggregator_type;

	async_result_type result(sess);

	auto handler = std::make_shared<aggregator_type>(result, std::distance(begin, end));
	auto on_entry = bind_method(handler, &aggregator_type::on_entry);
	auto on_finished = bind_method(handler, &aggregator_type::on_finished);

	for (auto it = begin; it != end; ++it) {
		it->connect(on_entry, on_finished);
	}

	return result;
}

} }

#endif // FUNCTIONAL_P_H
