#ifndef LOCAL_SESSION_H
#define LOCAL_SESSION_H

#include "../library/elliptics.h"
#include "../include/elliptics/session.hpp"

enum update_index_action {
	insert_data = 1,
	remove_data = 2
};

/* matches above enum, please update synchronously */
static const char *update_index_action_strings[] = {
	"empty",
	"insert",
	"remove",
};

class local_session
{
	ELLIPTICS_DISABLE_COPY(local_session)
	public:
		local_session(dnet_node *node);
		~local_session();

		void set_ioflags(uint32_t flags);

		ioremap::elliptics::data_pointer read(const dnet_id &id, int *errp);
		int write(const dnet_id &id, const ioremap::elliptics::data_pointer &data);
		int write(const dnet_id &id, const char *data, size_t size);

		int update_index_internal(const dnet_id &id, const dnet_raw_id &index, const ioremap::elliptics::data_pointer &data, update_index_action action);

	private:
		void clear_queue(int *errp = NULL);

		uint32_t m_flags;
		dnet_net_state *m_state;
};

#endif // LOCAL_SESSION_H
