#ifndef DNET_IOREMAP_ELLIPTICS_ASYNC_RESULT_CAST_HPP
#define DNET_IOREMAP_ELLIPTICS_ASYNC_RESULT_CAST_HPP

#include "callback_cast.hpp"
#include <elliptics/session.hpp>

namespace ioremap { namespace elliptics {

namespace detail
{

template <typename T>
struct async_result_cast_handler
{
	async_result_handler<T> handler;

	void operator() (const callback_result_entry &entry)
	{
		T new_entry = callback_cast<T>(entry);
		if (new_entry.is_valid())
			handler.process(new_entry);
	}

	void operator() (const error_info &error)
	{
		handler.complete(error);
	}
};

}

template <typename T>
async_result<T> async_result_cast(const session &sess, async_generic_result &&result)
{
	async_result<T> new_result(sess);
	detail::async_result_cast_handler<T> handler = {
		new_result
	};
	handler.handler.set_total(result.total());

	async_generic_result tmp = std::move(result);
	tmp.connect(handler, handler);

	return new_result;
}

}} /* namespace ioremap::elliptics */

#endif // DNET_IOREMAP_ELLIPTICS_ASYNC_RESULT_CAST_HPP

