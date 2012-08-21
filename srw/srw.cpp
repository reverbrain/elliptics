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
#include <boost/algorithm/string.hpp>
#include <boost/lexical_cast.hpp>
#include <boost/thread.hpp>
#include <boost/thread/condition.hpp>

#include <zmq.hpp>

#include <cocaine/context.hpp>
#include <cocaine/logging.hpp>
#include <cocaine/app.hpp>
#include <cocaine/job.hpp>

#include <elliptics/interface.h>
#include <elliptics/srw.h>

#include "elliptics.h"

class srw_log {
	public:
		srw_log(struct dnet_node *node, int level, const std::string &app, const std::string &message) : m_n(node) {
			dnet_log(m_n, level, "dnet-sink: %s : %s\n", app.c_str(), message.c_str());
			return;

			if (!boost::starts_with(app, "app/") || (level > node->log->log_level))
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
			dnet_transform(m_n, app_log.data(), app_log.size(), &ctl.id);

			ctl.fd = -1;

			char *result = NULL;
			int err = dnet_write_data_wait(m_n, &ctl, (void **)&result);
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
		struct dnet_node *m_n;

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
			cmd->id.group_id = m_n->id.group_id;
			cmd->cmd = DNET_CMD_WRITE;
			cmd->size = data.size() - sizeof(struct dnet_cmd);

			memcpy(io->parent, cmd->id.id, DNET_ID_SIZE);
			memcpy(io->id, cmd->id.id, DNET_ID_SIZE);

			io->flags = DNET_IO_FLAGS_APPEND | DNET_IO_FLAGS_SKIP_SENDING;
			io->size = msg.size();

			memcpy(msg_data, msg.data(), msg.size());

			m_n->cb->command_handler(m_n->st, m_n->cb->command_private, cmd, (void *)(cmd + 1));
		}
};

class dnet_sink_t: public cocaine::logging::sink_t {
	public:
		dnet_sink_t(struct dnet_node *n, cocaine::logging::priorities prio): cocaine::logging::sink_t(prio), m_n(n) {
		}

		virtual void emit(cocaine::logging::priorities prio, const std::string &app, const std::string& message) const {
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
				srw_log log(m_n, level, app, message);
		}

	private:
		struct dnet_node *m_n;
};

class dnet_job_t: public cocaine::engine::job_t
{
	public:
		dnet_job_t(struct dnet_node *n, const std::string& event, const cocaine::blob_t& blob):
		cocaine::engine::job_t(event, blob),
		m_completed(false),
		m_name(event),
       		m_n(n) {
		}

		virtual void react(const cocaine::engine::events::chunk& event) {
			dnet_log(m_n, DNET_LOG_INFO, "chunk: %.*s\n", (int)event.message.size(), (char *)event.message.data());

			boost::mutex::scoped_lock guard(m_lock);
			m_res.insert(m_res.end(), (char *)event.message.data(), (char *)event.message.data() + event.message.size());
		}

		virtual void react(const cocaine::engine::events::choke& ) {
			srw_log log(m_n, DNET_LOG_NOTICE, "app/" + m_name, "processing completed");
		}

		virtual void react(const cocaine::engine::events::error& event) {
			srw_log log(m_n, DNET_LOG_ERROR, "app/" + m_name, event.message + ": " + boost::lexical_cast<std::string>(event.code));
		}

		void reply(bool completed, const char *reply, size_t size) {
			boost::mutex::scoped_lock guard(m_lock);
			if (reply && size)
				m_res.insert(m_res.end(), reply, reply + size);
			m_completed = completed;
			m_cond.notify_all();
		}

		bool wait(long timeout) {
			boost::system_time const abs_time = boost::get_system_time()+ boost::posix_time::seconds(timeout);

			while (!m_completed) {
				boost::mutex::scoped_lock guard(m_lock);
				if (!m_cond.timed_wait(guard, abs_time))
					return false;
			}

			return true;
		}

		std::vector<char> &result(void) {
			return m_res;
		}

	private:
		bool m_completed;
		std::string m_name;
		struct dnet_node *m_n;
		std::vector<char> m_res;
		boost::mutex m_lock;
		boost::condition m_cond;
};

typedef boost::shared_ptr<dnet_job_t> dnet_shared_job_t;

class app_watcher {
	public:
		app_watcher(cocaine::context_t &ctx, const std::string &app) :
		m_need_exit(false),
		m_thread(boost::bind(&app_watcher::process, this)) {
			m_app.reset(new cocaine::app_t(ctx, app));
			m_app->start();
		}

		~app_watcher() {
			boost::mutex::scoped_lock guard(m_lock);
			m_need_exit = true;
			m_cond.notify_one();
			guard.unlock();

			m_thread.join();
		}

		void push(dnet_shared_job_t job) {
			boost::mutex::scoped_lock guard(m_lock);

			m_jobs.push_back(job);
			m_cond.notify_one();
		}

		std::string info() {
			return Json::FastWriter().write(m_app->info());
		}

	private:
		bool m_need_exit;
		boost::condition m_cond;
		boost::mutex m_lock;
		std::deque<dnet_shared_job_t> m_jobs;
		boost::thread m_thread;
		std::auto_ptr<cocaine::app_t> m_app;

		void process() {
			while (!m_need_exit) {

				boost::mutex::scoped_lock guard(m_lock);
				if (m_jobs.empty()) {
					m_cond.wait(guard);
				}

				if (m_need_exit)
					break;

				if (!m_jobs.empty()) {
					dnet_shared_job_t job = m_jobs.front();
					m_jobs.pop_front();
					guard.unlock();

					m_app->enqueue(job, cocaine::engine::mode::blocking);
				}
			}
		}

};

typedef std::map<std::string, boost::shared_ptr<app_watcher> > eng_map_t;
typedef std::map<int, dnet_shared_job_t> jobs_map_t;

namespace {
	cocaine::logging::priorities dnet_log_level_to_prio(int level) {
		cocaine::logging::priorities prio = cocaine::logging::ignore;
		if (level == DNET_LOG_DEBUG)
			prio = cocaine::logging::debug;
		else if (level == DNET_LOG_INFO)
			prio = cocaine::logging::info;
		else if (level == DNET_LOG_NOTICE)
			prio = cocaine::logging::info;
		else if (level == DNET_LOG_ERROR)
			prio = cocaine::logging::error;

		return prio;
	}
}

class srw {
	public:
		srw(struct dnet_node *n, const std::string &config) : m_n(n),
		m_ctx(config, boost::make_shared<dnet_sink_t>(n, dnet_log_level_to_prio(m_n->log->log_level))) {
		}

		~srw() {
			/* no need to iterate over engines, its destructor automatically stops it */
#if 0
			for (eng_map_t::iterator it = m_map.begin(); it != m_map.end(); ++it) {
				it->second->stop();
			}
#endif
		}

		int process(struct dnet_net_state *st, struct dnet_cmd *cmd, struct sph *sph) {
			char *data = (char *)(sph + 1);
			std::string event = dnet_get_event(sph, data);

			std::vector<std::string> strs;
			boost::split(strs, event, boost::is_any_of("@"));

			if (strs.size() != 2) {
				dnet_log(m_n, DNET_LOG_ERROR, "%s: invalid event name: must be application@event or application@start-task\n",
						event.c_str());
				return -EINVAL;
			}

			std::string app = strs[0];
			std::string ev = strs[1];

			if (ev == "start-task") {
				boost::shared_ptr<app_watcher> eng(new app_watcher(m_ctx, app));

				boost::mutex::scoped_lock guard(m_lock);
				m_map.insert(std::make_pair(app, eng));

				dnet_log(m_n, DNET_LOG_NOTICE, "%s: task started: %s\n", event.c_str(), app.c_str());
				return 0;
			} else if (ev == "stop-task") {
				boost::mutex::scoped_lock guard(m_lock);
				eng_map_t::iterator it = m_map.find(app);
				/* destructor stops engine */
				if (it != m_map.end())
					m_map.erase(it);
				guard.unlock();

				dnet_log(m_n, DNET_LOG_NOTICE, "%s: task stopped: %s\n", event.c_str(), app.c_str());
				return 0;
			} else if (ev == "info") {
				boost::mutex::scoped_lock guard(m_lock);
				eng_map_t::iterator it = m_map.find(app);
				if (it == m_map.end()) {
					dnet_log(m_n, DNET_LOG_ERROR, "%s: no task '%s' started\n", event.c_str(), app.c_str());
					return -ENOENT;
				}

				std::string s = it->second->info();
				dnet_log(m_n, DNET_LOG_INFO, "app engine: %s\n", s.c_str());
				return dnet_send_reply(st, cmd, (void *)s.data(), s.size(), 0);
			} else if (sph->flags & (DNET_SPH_FLAGS_REPLY | DNET_SPH_FLAGS_FINISH)) {
				boost::mutex::scoped_lock guard(m_lock);

				jobs_map_t::iterator it = m_jobs.find(sph->src_key);
				if (it == m_jobs.end()) {
					dnet_log(m_n, DNET_LOG_ERROR, "%s: %s: no job(%x) to complete\n",
							event.c_str(), dnet_dump_id(&cmd->id), sph->src_key);
					return -ENOENT;
				}

				bool final = sph->flags & DNET_SPH_FLAGS_FINISH;
				it->second->reply(final, (char *)sph, total_size(sph) + sizeof(struct sph));
				dnet_log(m_n, DNET_LOG_INFO, "%s: task completed(%x), total-data-size: %zd, finish: %d\n",
						event.c_str(), sph->src_key, total_size(sph), final);

				if (final)
					m_jobs.erase(it);
				return 0;
			} else {
				if (sph->flags & DNET_SPH_FLAGS_SRC_BLOCK) {
					sph->src_key = (unsigned long)sph;
					memcpy(sph->src.id, cmd->id.id, sizeof(sph->src.id));
				}

				dnet_shared_job_t job(boost::make_shared<dnet_job_t>(m_n, ev,
						cocaine::blob_t((const char *)sph, total_size(sph) + sizeof(struct sph))));

				boost::mutex::scoped_lock guard(m_lock);
				eng_map_t::iterator it = m_map.find(app);
				if (it == m_map.end()) {
					dnet_log(m_n, DNET_LOG_ERROR, "%s: no task '%s' started\n", event.c_str(), app.c_str());
					return -ENOENT;
				}

				if (sph->flags & DNET_SPH_FLAGS_SRC_BLOCK)
					m_jobs.insert(std::make_pair(sph->src_key, job));

				it->second->push(job);
				guard.unlock();

				dnet_log(m_n, DNET_LOG_INFO, "%s: task queued(%x), total-data-size: %zd, block: %d\n",
						event.c_str(), sph->src_key, total_size(sph), !!(sph->flags & DNET_SPH_FLAGS_SRC_BLOCK));

				int err = 0;
				if (sph->flags & DNET_SPH_FLAGS_SRC_BLOCK) {
					bool success = job->wait(m_n->wait_ts.tv_sec);
					if (!success)
						throw std::runtime_error("timeout waiting for exec command to complete");

					std::vector<char> res = job->result();
					if (res.size()) {
						err = dnet_send_reply(st, cmd, res.data(), res.size(), 0);
					}
				}

				return err;
			}
		}

	private:
		struct dnet_node		*m_n;
		cocaine::context_t		m_ctx;
		boost::mutex			m_lock;
		eng_map_t			m_map;
		jobs_map_t			m_jobs;

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
		dnet_node_set_groups(n, (int *)&n->id.group_id, 1);
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
