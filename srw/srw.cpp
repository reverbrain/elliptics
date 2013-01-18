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
#include <boost/thread.hpp>
#include <boost/thread/condition.hpp>

#include <zmq.hpp>

#include <cocaine/context.hpp>
#include <cocaine/logging.hpp>
#include <cocaine/app.hpp>
#include <cocaine/exceptions.hpp>
#include <cocaine/api/event.hpp>
#include <cocaine/api/stream.hpp>
#include <cocaine/api/service.hpp>

#include <elliptics/interface.h>
#include <elliptics/srw.h>

#include "elliptics.h"

class srw_log {
	public:
		srw_log(struct dnet_session *session, int level, const std::string &app, const std::string &message) : m_s(session) {
			dnet_log(session->node, level, "srw: %s : %s\n", app.c_str(), message.c_str());
			return;

			if (!strncmp(app.data(), "app/", 4) || (level > m_s->node->log->log_level))
				return;

			std::string msg_with_date;

			char str[64];
			struct tm tm;
			struct timeval tv;

			gettimeofday(&tv, NULL);
			localtime_r((time_t *)&tv.tv_sec, &tm);
			strftime(str, sizeof(str), "%F %R:%S", &tm);

			char tmp[128];

			int len = snprintf(tmp, sizeof(tmp), "%s.%06lu %ld/%4d %1d: ", str, tv.tv_usec, dnet_get_id(), getpid(), level);
			msg_with_date.assign(tmp, len);
			msg_with_date += message + "\n";

			struct dnet_io_control ctl;

			memset(&ctl, 0, sizeof(ctl));

			ctl.cflags = 0;
			ctl.data = msg_with_date.data();

			ctl.io.flags = DNET_IO_FLAGS_APPEND;
			ctl.io.size = msg_with_date.size();

			std::string app_log = app + ".log";
			dnet_transform(m_s->node, app_log.data(), app_log.size(), &ctl.id);

			ctl.fd = -1;

			char *result = NULL;
			int err = dnet_write_data_wait(m_s, &ctl, (void **)&result);
			if (err < 0) {
				/* could not find remote node to send data, saving it locally */
				if (err == -ENOENT) {
					log_locally(ctl.id, msg_with_date);
					return;
				}

				std::ostringstream string;
				string << dnet_dump_id(&ctl.id) << ": WRITE: log-write-failed: size: " << message.size() << ", err: " << err;
				throw std::runtime_error(string.str());
			}

			free(result);
		}

	private:
		struct dnet_session *m_s;

		void log_locally(struct dnet_id &id, const std::string &msg) const {
			std::vector<char> data;
			struct dnet_cmd *cmd;
			struct dnet_io_attr *io;
			char *msg_data;

			data.resize(sizeof(struct dnet_cmd) + sizeof(struct dnet_io_attr) + msg.size());

			cmd = (struct dnet_cmd *)data.data();
			io = (struct dnet_io_attr *)(cmd + 1);
			msg_data = (char *)(io + 1);

			cmd->id = id;
			cmd->id.group_id = m_s->node->id.group_id;
			cmd->cmd = DNET_CMD_WRITE;
			cmd->size = data.size() - sizeof(struct dnet_cmd);

			memcpy(io->parent, cmd->id.id, DNET_ID_SIZE);
			memcpy(io->id, cmd->id.id, DNET_ID_SIZE);

			io->flags = DNET_IO_FLAGS_APPEND | DNET_IO_FLAGS_SKIP_SENDING;
			io->size = msg.size();

			memcpy(msg_data, msg.data(), msg.size());

			m_s->node->cb->command_handler(m_s->node->st, m_s->node->cb->command_private, cmd, (void *)(cmd + 1));
		}
};

class dnet_sink_t: public cocaine::logging::logger_t {
	public:
		dnet_sink_t(struct dnet_session *sess, cocaine::logging::priorities prio):
		m_s(sess), m_prio(prio) {
		}

		virtual cocaine::logging::priorities verbosity() const {
			return m_prio;
		}

		virtual void emit(cocaine::logging::priorities prio, const std::string &app, const std::string& message) {
			int level = DNET_LOG_NOTICE;
			if (prio == cocaine::logging::debug)
				level = DNET_LOG_DEBUG;
			if (prio == cocaine::logging::info)
				level = DNET_LOG_INFO;
			if (prio == cocaine::logging::warning)
				level = DNET_LOG_INFO;
			if (prio == cocaine::logging::error)
				level = DNET_LOG_ERROR;
			if (prio == cocaine::logging::ignore)
				level = -1;

			if (level != -1)
				srw_log log(m_s, level, app, message);
		}

	private:
		struct dnet_session *m_s;
		cocaine::logging::priorities m_prio;
};

class dnet_upstream_t: public cocaine::api::stream_t
{
	public:
		dnet_upstream_t(struct dnet_session *session, struct dnet_net_state *state, struct dnet_cmd *cmd,
				const std::string &event, uint64_t sph_flags):
		m_completed(false),
		m_name(event),
       		m_s(session),
       		m_state(dnet_state_get(state)),
       		m_cmd(*cmd),
		m_sph_flags(sph_flags),
       		m_error(0) {
		}

		~dnet_upstream_t() {
			reply(true, NULL, 0);
		}

		virtual void push(const char *chunk, size_t size) {
			boost::mutex::scoped_lock guard(m_lock);
			m_res.insert(m_res.end(), chunk, chunk + size);

			std::ostringstream msg;
			msg << "received reply chunk: size: " << size << ", data: '" << chunk << "', " <<
				"accumulated-reply-size: " << m_res.size() << std::endl;

			srw_log log(m_s, DNET_LOG_NOTICE, "app/" + m_name, msg.str());
		}

		static std::string lexical_cast(size_t value) {
			if (value == 0) {
				return std::string("0");
			}
			std::string result;
			size_t length = 0;
			size_t calculated = value;
			while (calculated) {
				calculated /= 10;
				++length;
			}
			result.resize(length);
			while (value) {
				--length;
				result[length] = '0' + (value % 10);
				value /= 10;
			}
			return result;
		}

		virtual void close(void) {
			srw_log log(m_s, DNET_LOG_NOTICE, "app/" + m_name, "job completed, data size: " +
					lexical_cast(m_res.size()));
		}

		virtual void error(cocaine::error_code code, const std::string &message) {
			m_error = -code;
			srw_log log(m_s, DNET_LOG_ERROR, "app/" + m_name, message + ": " + lexical_cast(code));
		}

		void reply(bool completed, const char *reply, size_t size) {
			if (reply && size) {
				boost::mutex::scoped_lock guard(m_lock);
				m_res.insert(m_res.end(), reply, reply + size);
			}

			if (completed && m_state) {
				boost::mutex::scoped_lock guard(m_lock);
				if (m_state && (m_sph_flags & DNET_SPH_FLAGS_SRC_BLOCK)) {
					if (m_res.size()) {
						m_cmd.flags &= ~DNET_FLAGS_NEED_ACK;
						dnet_send_reply(m_state, &m_cmd, m_res.data(), m_res.size(), 0);
					} else {
						m_cmd.flags |= DNET_FLAGS_NEED_ACK;
						dnet_send_ack(m_state, &m_cmd, m_error);
					}
				}

				dnet_state_put(m_state);
				m_state = NULL;
				m_res.clear();
			}
		}

		std::vector<char> &result(void) {
			return m_res;
		}

	private:
		bool m_completed;
		std::string m_name;
		struct dnet_session *m_s;
		std::vector<char> m_res;
		boost::mutex m_lock;
		struct dnet_net_state *m_state;
		struct dnet_cmd m_cmd;
		uint64_t m_sph_flags;
		int m_error;
};

typedef boost::shared_ptr<dnet_upstream_t> dnet_shared_upstream_t;
typedef std::map<std::string, boost::shared_ptr<cocaine::app_t> > eng_map_t;
typedef std::map<int, dnet_shared_upstream_t> jobs_map_t;

namespace {
	cocaine::logging::priorities dnet_log_level_to_prio(int level) {
		cocaine::logging::priorities prio = (cocaine::logging::priorities)level;
		return prio;
	}
}

class srw {
	public:
		srw(struct dnet_session *sess, const std::string &config) : m_s(sess),
		m_ctx(config, std::unique_ptr<dnet_sink_t>(new dnet_sink_t(m_s, dnet_log_level_to_prio(sess->node->log->log_level)))) {
		//m_ctx(config, "core") {
			atomic_set(&m_src_key, 1);

			m_cocaine_logger = cocaine::api::service(m_ctx, "logging");
			m_cocaine_logger->run();
		}

		~srw() {
			m_cocaine_logger->terminate();
			/* no need to iterate over engines, its destructor automatically stops it */
#if 0
			for (eng_map_t::iterator it = m_map.begin(); it != m_map.end(); ++it) {
				it->second->stop();
			}
#endif
		}

		int process(struct dnet_net_state *st, struct dnet_cmd *cmd, struct sph *sph) {
			int err = 0;
			char *data = (char *)(sph + 1);
			std::string event = dnet_get_event(sph, data);

			char id_str[DNET_DUMP_NUM * 2 + 1];
			char sph_str[DNET_DUMP_NUM * 2 + 1];

			dnet_dump_id_len_raw(cmd->id.id, DNET_DUMP_NUM, id_str);
			dnet_dump_id_len_raw(sph->src.id, DNET_DUMP_NUM, sph_str);

			id_str[2 * DNET_DUMP_NUM] = '\0';
			sph_str[2 * DNET_DUMP_NUM] = '\0';

			char *ptr = strchr((char *)event.c_str(), '@');
			if (!ptr) {
				dnet_log(m_s->node, DNET_LOG_ERROR, "%s: sph: %s: %s: invalid event name: "
						"must be application@event or application@start-task\n",
						id_str, sph_str, event.c_str());
				return -EINVAL;
			}

			std::string app(event.c_str(), ptr - event.c_str());
			std::string ev(ptr+1);

			if (ev == "start-task") {
				boost::mutex::scoped_lock guard(m_lock);
				eng_map_t::iterator it = m_map.find(app);
				if (it == m_map.end()) {
					boost::shared_ptr<cocaine::app_t> eng(new cocaine::app_t(m_ctx, app, app));
					eng->start();

					m_map.insert(std::make_pair(app, eng));
					dnet_log(m_s->node, DNET_LOG_INFO, "%s: sph: %s: %s: started\n", id_str, sph_str, event.c_str());
				} else {
					dnet_log(m_s->node, DNET_LOG_INFO, "%s: sph: %s: %s: was already started\n",
							id_str, sph_str, event.c_str());
				}
			} else if (ev == "stop-task") {
				boost::mutex::scoped_lock guard(m_lock);
				eng_map_t::iterator it = m_map.find(app);
				/* destructor stops engine */
				if (it != m_map.end())
					m_map.erase(it);
				guard.unlock();

				dnet_log(m_s->node, DNET_LOG_INFO, "%s: sph: %s: %s: stopped\n", id_str, sph_str, event.c_str());
			} else if (ev == "info") {
				boost::mutex::scoped_lock guard(m_lock);
				eng_map_t::iterator it = m_map.find(app);
				if (it == m_map.end()) {
					dnet_log(m_s->node, DNET_LOG_ERROR, "%s: sph: %s: %s: no task\n", id_str, sph_str, event.c_str());
					return -ENOENT;
				}

				std::string s = Json::FastWriter().write(it->second->info());
				dnet_log(m_s->node, DNET_LOG_INFO, "%s: sph: %s: %s: info: %s\n", id_str, sph_str, event.c_str(), s.c_str());
				err = dnet_send_reply(st, cmd, (void *)s.data(), s.size(), 0);
			} else if (sph->flags & (DNET_SPH_FLAGS_REPLY | DNET_SPH_FLAGS_FINISH)) {
				bool final = sph->flags & DNET_SPH_FLAGS_FINISH;

				boost::mutex::scoped_lock guard(m_lock);

				jobs_map_t::iterator it = m_jobs.find(sph->src_key);
				if (it == m_jobs.end()) {
					dnet_log(m_s->node, DNET_LOG_ERROR, "%s: sph: %s: %s: no job: %d to complete\n",
						id_str, sph_str, event.c_str(), sph->src_key);
					return -ENOENT;
				}

				dnet_shared_upstream_t upstream = it->second;
				if (final)
					m_jobs.erase(it);

				guard.unlock();

				upstream->reply(final, (char *)(sph + 1) + sph->event_size, sph->data_size + sph->binary_size);

				dnet_log(m_s->node, DNET_LOG_INFO, "%s: sph: %s: %s: completed: job: %d, total-size: %zd, finish: %d\n",
						id_str, sph_str, event.c_str(), sph->src_key, total_size(sph), final);

			} else {
				if (sph->flags & DNET_SPH_FLAGS_SRC_BLOCK) {
					sph->src_key = atomic_inc(&m_src_key);
					memcpy(sph->src.id, cmd->id.id, sizeof(sph->src.id));
				}

				cocaine::api::event_t cevent(event);
				dnet_shared_upstream_t upstream(boost::make_shared<dnet_upstream_t>(m_s, st, cmd, event, (uint64_t)sph->flags));

				boost::mutex::scoped_lock guard(m_lock);
				eng_map_t::iterator it = m_map.find(app);
				if (it == m_map.end()) {
					dnet_log(m_s->node, DNET_LOG_ERROR, "%s: sph: %s: %s: no task\n", id_str, sph_str, event.c_str());
					return -ENOENT;
				}

				if (sph->flags & DNET_SPH_FLAGS_SRC_BLOCK)
					m_jobs.insert(std::make_pair((int)sph->src_key, upstream));

				boost::shared_ptr<cocaine::app_t> app = it->second;
				guard.unlock();

				boost::shared_ptr<cocaine::api::stream_t> stream = app->enqueue(cevent, upstream);
				stream->push((const char *)sph, total_size(sph) + sizeof(struct sph));

				dnet_log(m_s->node, DNET_LOG_INFO, "%s: sph: %s: %s: started: job: %d, total-size: %zd, block: %d\n",
						id_str, sph_str, event.c_str(),
						sph->src_key, total_size(sph),
						!!(sph->flags & DNET_SPH_FLAGS_SRC_BLOCK));

				if (sph->flags & DNET_SPH_FLAGS_SRC_BLOCK) {
					cmd->flags &= ~DNET_FLAGS_NEED_ACK;
				}
			}

			return err;
		}

	private:
		struct dnet_session		*m_s;
		cocaine::context_t		m_ctx;
		boost::mutex			m_lock;
		eng_map_t			m_map;
		jobs_map_t			m_jobs;
		atomic_t			m_src_key;
		cocaine::api::category_traits<cocaine::api::service_t>::ptr_type m_cocaine_logger;

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
		dnet_session *s = dnet_session_create(n);
		dnet_session_set_groups(s, (int *)&n->id.group_id, 1);
		n->srw = (void *)new srw(s, cfg->srw.config);
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

	if (!s)
		return -ENOTSUP;

	try {
		return s->process(st, cmd, header);
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
