/*
 * 2011+ Copyright (c) Evgeniy Polyakov <zbr@ioremap.net>
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

#include "config.h"

#include <sys/types.h>
#include <sys/stat.h>
#include <sys/socket.h>
#include <sys/mman.h>
#include <sys/wait.h>

#include <ctype.h>
#include <fcntl.h>
#include <limits.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>

#ifdef HAVE_COCAINE_SUPPORT

#include <map>
#include <vector>
#include <boost/algorithm/string.hpp>

#include <zmq.hpp>

#include <cocaine/context.hpp>
#include <cocaine/logging.hpp>
#include <cocaine/app.hpp>
#include <cocaine/job.hpp>

#include <elliptics/cppdef.h>
#include <elliptics/srw.h>

#include "elliptics.h"

class dnet_sink_t: public cocaine::logging::sink_t {
	public:
		dnet_sink_t(struct dnet_node *n): cocaine::logging::sink_t(cocaine::logging::debug), m_n(n) {
		}

		virtual void emit(cocaine::logging::priorities prio, const std::string& message) const {
			int mask = DNET_LOG_NOTICE;
			if (prio == cocaine::logging::debug)
				mask = DNET_LOG_NOTICE;
			if (prio == cocaine::logging::info)
				mask = DNET_LOG_INFO;
			if (prio == cocaine::logging::warning)
				mask = DNET_LOG_INFO;
			if (prio == cocaine::logging::error)
				mask = DNET_LOG_ERROR;
			if (prio == cocaine::logging::ignore)
				mask = DNET_LOG_DSA;

			dnet_log(m_n, mask, "dnet-sink: %s\n", message.c_str());
		}

	private:
		struct dnet_node *m_n;

};

class dnet_job_t: public cocaine::engine::job_t
{
	public:
		dnet_job_t(struct dnet_node *n, const std::string& event, const cocaine::blob_t& blob):
		cocaine::engine::job_t(event, blob),
       		m_n(n) {
		}

		virtual void react(const cocaine::engine::events::chunk& event) {
			dnet_log(m_n, DNET_LOG_INFO, "chunk: %.*s\n", (int)event.message.size(), (char *)event.message.data());
			m_res.insert(m_res.end(), (char *)event.message.data(), (char *)event.message.data() + event.message.size());
		}

		virtual void react(const cocaine::engine::events::choke& ) {
			dnet_log(m_n, DNET_LOG_INFO, "choke: %.*s\n", (int)m_res.size(), m_res.data());
		}

		virtual void react(const cocaine::engine::events::error& event) {
			dnet_log(m_n, DNET_LOG_ERROR, "error: %s: %d\n", event.message.c_str(), event.code);
		}

	private:
		struct dnet_node *m_n;
		std::vector<char> m_res;
};

typedef std::map<std::string, boost::shared_ptr<cocaine::app_t> > eng_map_t;

class srw {
	public:
		srw(struct dnet_node *n, const std::string &config) : m_n(n), m_ctx(config, boost::make_shared<dnet_sink_t>(n)) {
		}

		~srw() {
			/* no need to iterate over engines, its destructor automatically stops it */
#if 0
			for (eng_map_t::iterator it = m_map.begin(); it != m_map.end(); ++it) {
				it->second->stop();
			}
#endif
		}

		int process(const struct sph *sph) {
			char *data = (char *)(sph + 1);
			std::string event = dnet_get_event(sph, data);

			std::vector<std::string> strs;
			boost::split(strs, event, boost::is_any_of("@"));

			if (strs.size() != 2) {
				dnet_log(m_n, DNET_LOG_ERROR, "%s: invalid event name: must be application@event or start-task@name\n",
						event.c_str());
				return -EINVAL;
			}

			if (strs[0] == "start-task") {
				boost::shared_ptr<cocaine::app_t> eng(new cocaine::app_t(m_ctx, strs[1]));
    				eng->start();

				boost::mutex::scoped_lock guard(m_lock);
				m_map.insert(std::make_pair(strs[1], eng));

				dnet_log(m_n, DNET_LOG_NOTICE, "%s: task started: %s\n", event.c_str(), strs[1].c_str());
				return 0;
			} if (strs[0] == "stop-task") {
				boost::mutex::scoped_lock guard(m_lock);
				eng_map_t::iterator it = m_map.find(strs[1]);
				/* destructor stops engine */
				if (it != m_map.end())
					m_map.erase(it);
				guard.unlock();

				dnet_log(m_n, DNET_LOG_NOTICE, "%s: task stopped: %s\n", event.c_str(), strs[1].c_str());
				return 0;
			} else {
				boost::mutex::scoped_lock guard(m_lock);
				eng_map_t::iterator it = m_map.find(strs[0]);
				if (it == m_map.end())
					return -ENOENT;

				guard.unlock();

				it->second->enqueue(boost::make_shared<dnet_job_t>(m_n, strs[1],
							cocaine::blob_t((const char *)sph, total_size(sph) + sizeof(struct sph))));
				dnet_log(m_n, DNET_LOG_NOTICE, "%s: task queued\n", strs[1].c_str());
				return 0;
			}
		}

	private:
		struct dnet_node		*m_n;
		cocaine::context_t		m_ctx;
		boost::mutex			m_lock;
		eng_map_t			m_map;

		std::string dnet_get_event(const struct sph *sph, const char *data) {
			return std::string(data, sph->event_size);
		}

		size_t total_size(const struct sph *sph) {
			return sph->event_size + sph->data_size + sph->binary_size;
		}
};

int dnet_srw_init(struct dnet_node *n, struct dnet_config *cfg)
{
	int err = 0;

	if (!cfg->srw.config) {
		dnet_log(n, DNET_LOG_ERROR, "srw: no config\n");
		return -ENOTSUP;
	}

	try {
		n->srw = (void *)new srw(n, cfg->srw.config);
		dnet_log(n, DNET_LOG_INFO, "srw: initialized: config: %s\n", cfg->srw.config);
		return 0;
	} catch (const std::exception &e) {
		dnet_log(n, DNET_LOG_ERROR, "srw: init failed: config: %s, exception: %s\n", cfg->srw.config, e.what());
		err = -ENOMEM;
	}

	return err;
}

void dnet_srw_cleanup(struct dnet_node *n)
{
	if (n->srw) {
		try {
			delete (srw *)n->srw;
		} catch (...) {
		}

		n->srw = NULL;
	}
}

int dnet_cmd_exec_raw(struct dnet_net_state *st, struct dnet_cmd *cmd, struct sph *header, const void *data)
{
	struct dnet_node *n = st->n;
	srw *s = (srw *)n->srw;

	try {
		return s->process(header);
	} catch (const std::exception &e) {
		dnet_log(n, DNET_LOG_ERROR, "%s: srw-processing: event: %.*s, data-size: %lld, binary-size: %lld, exception: %s\n",
				dnet_dump_id(&cmd->id), header->event_size, (const char *)data,
				(unsigned long long)header->data_size, (unsigned long long)header->binary_size,
				e.what());
	}

	return -EINVAL;
}

int dnet_srw_update(struct dnet_node *, int )
{
	return 0;
}
#else
#include <errno.h>

#include "elliptics.h"

int dnet_srw_init(struct dnet_node *, struct dnet_config *)
{
	return -ENOTSUP;
}

void dnet_srw_cleanup(struct dnet_node *)
{
}

int dnet_cmd_exec_raw(struct dnet_net_state *, struct dnet_cmd *, struct sph *, const void *)
{
	return -ENOTSUP;
}

int dnet_srw_update(struct dnet_node *, int)
{
	return 0;
}
#endif
