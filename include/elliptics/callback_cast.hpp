#ifndef DNET_IOREMAP_ELLIPTICS_CAST_HPP
#define DNET_IOREMAP_ELLIPTICS_CAST_HPP

#include "result_entry.hpp"
#include <elliptics/packet.h>

namespace ioremap { namespace elliptics {

namespace detail
{

template <typename T>
struct callback_result_types;

inline bool has_command(const std::initializer_list<dnet_commands> &container, int value)
{
	return std::find(container.begin(), container.end(), value) != container.end();
}

#define INIT_CALLBACK_TYPE(Type, ...) \
	template <> \
	struct callback_result_types<Type> \
	{ \
		static bool can_cast(int command) \
		{ \
			return has_command({ __VA_ARGS__ }, command); \
		} \
	};

INIT_CALLBACK_TYPE(read_result_entry,
	DNET_CMD_READ,
	DNET_CMD_READ_RANGE,
	DNET_CMD_DEL_RANGE,
	DNET_CMD_BULK_READ
)

INIT_CALLBACK_TYPE(lookup_result_entry,
	DNET_CMD_LOOKUP,
	DNET_CMD_WRITE
)

INIT_CALLBACK_TYPE(monitor_stat_result_entry,
	DNET_CMD_MONITOR_STAT
)

INIT_CALLBACK_TYPE(node_status_result_entry,
	DNET_CMD_STATUS
)

INIT_CALLBACK_TYPE(exec_result_entry,
	DNET_CMD_EXEC
)

INIT_CALLBACK_TYPE(iterator_result_entry,
	DNET_CMD_ITERATOR
)

INIT_CALLBACK_TYPE(backend_status_result_entry,
	DNET_CMD_BACKEND_CONTROL,
	DNET_CMD_BACKEND_STATUS
)

template <typename T>
struct callback_result_traits
{
	static bool can_cast(int command)
	{
		return callback_result_types<T>::can_cast(command);
	}
};

template <>
struct callback_result_traits<callback_result_entry>
{
	static bool can_cast(int)
	{
		return true;
	}
};

}

template <typename T>
T callback_cast(const callback_result_entry &entry)
{
	if (detail::callback_result_traits<T>::can_cast(entry.command()->cmd))
		return static_cast<const T &>(entry);
	return T();
}

}} /* namespace ioremap::elliptics */

#endif // DNET_IOREMAP_ELLIPTICS_CAST_HPP
