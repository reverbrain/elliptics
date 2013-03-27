/*
 * 2008+ Copyright (c) Evgeniy Polyakov <zbr@ioremap.net>
 * 2012+ Copyright (c) Ruslan Nigmatullin <euroelessar@yandex.ru>
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

#ifndef CALLBACK_P_H
#define CALLBACK_P_H

#include "../../include/elliptics/cppdef.h"

#include <exception>
#include <set>
#include <thread>
#include <mutex>
#include <condition_variable>
#include <algorithm>
#include <cassert>

#ifdef DEVELOPER_BUILD
#  define elliptics_assert(expr) assert(expr)
#else
#  define elliptics_assert(expr)
#endif

namespace ioremap { namespace elliptics {

typedef int (*complete_func)(struct dnet_net_state *, struct dnet_cmd *, void *);

class callback_result_data
{
	public:
		callback_result_data()
		{
		}

		callback_result_data(struct dnet_net_state *state, struct dnet_cmd *cmd)
		{
			const size_t size = sizeof(struct dnet_addr) + sizeof(struct dnet_cmd) + cmd->size;
			void *allocated = malloc(size);
			if (!allocated)
				throw std::bad_alloc();
			data = data_pointer(allocated, size);
			memcpy(data.data(), dnet_state_addr(state), sizeof(struct dnet_addr));
			memcpy(data.data<char>() + sizeof(struct dnet_addr), cmd, sizeof(struct dnet_cmd) + cmd->size);
		}

		virtual ~callback_result_data()
		{
		}

		data_pointer data;
		error_info error;
};

enum special_count { unlimited };
enum status_request { all_ok, any_ok };

class default_callback
{
	public:
		default_callback() : m_count(1), m_complete(0)
		{
		}

		virtual ~default_callback()
		{
		}

		bool set_count(size_t count)
		{
			std::lock_guard<std::mutex> lock(m_mutex);
			m_count = count;
			return m_count == m_complete;
		}

		void set_count(special_count)
		{
			std::lock_guard<std::mutex> lock(m_mutex);
			m_count = static_cast<size_t>(-1);
		}

		bool handle(struct dnet_net_state *state, struct dnet_cmd *cmd, complete_func, void *)
		{
			std::lock_guard<std::mutex> lock(m_mutex);

			if (is_trans_destroyed(state, cmd)) {
				++m_complete;
			} else {
				process(cmd, callback_result_data(state, cmd));
			}
			return (m_count == m_complete);
		}

		virtual void process(struct dnet_cmd *cmd, const callback_result_data &data)
		{
			if (!(cmd->flags & DNET_FLAGS_MORE))
				m_statuses.push_back(cmd->status);
			m_results.push_back(std::make_shared<callback_result_data>(data));
		}

		bool is_ready()
		{
			std::lock_guard<std::mutex> lock(m_mutex);
			return (m_count == m_complete);
		}

		template <typename T>
		T any_result() const
		{
			if (m_results.empty())
				return T();
			return *static_cast<const T *>(&m_results.front());
		}

		template <typename T>
		const T &result_at(size_t index) const
		{
			return *static_cast<const T *>(&m_results.at(index));
		}

		const callback_result_entry &result_at(size_t index) const
		{
			return m_results.at(index);
		}

		const std::vector<callback_result_entry> &results() const
		{
			return m_results;
		}

		const std::vector<int> &statuses() const
		{
			return m_statuses;
		}

		size_t results_size() const
		{
			return m_results.size();
		}

		bool is_valid() const
		{
			bool ok = false;
			for (size_t i = 0; i < m_statuses.size(); ++i)
				ok |= (m_statuses[i] == 0);
			return ok;
		}

		bool is_valid(status_request request) const
		{
			if (request == any_ok) {
				bool ok = false;
				for (size_t i = 0; i < m_statuses.size(); ++i)
					ok |= (m_statuses[i] == 0);
				return ok;
			} else if (request == all_ok) {
				bool ok = !m_statuses.empty();
				for (size_t i = 0; i < m_statuses.size(); ++i)
					ok &= (m_statuses[i] == 0);
				return ok;
			}
			abort();
		}

		void clear()
		{
			m_results.clear();
			m_statuses.clear();
			m_complete = 0;
		}

	private:
		std::vector<callback_result_entry> m_results;
		std::vector<int> m_statuses;
		size_t m_count;
		size_t m_complete;
		std::mutex m_mutex;
};

template <typename Result, dnet_commands Command>
class base_stat_callback : public default_callback
{
	public:
		base_stat_callback(const session &sess) : sess(sess), has_id(false)
		{
		}

		bool start(complete_func func, void *priv)
		{
			set_count(unlimited);

			uint64_t cflags_pop = sess.get_cflags();
			sess.set_cflags(cflags_pop | DNET_ATTR_CNTR_GLOBAL);
			int err = dnet_request_stat(sess.get_native(),
				has_id ? &id : NULL, Command, func, priv);
			sess.set_cflags(cflags_pop);
			if (err < 0) {
				throw_error(err, "Failed to request statistics");
			}

			return set_count(err);
		}

		void finish(std::exception_ptr exc)
		{
			if (exc != std::exception_ptr()) {
				handler(exc);
				return;
			}

			std::vector<Result> res;
			res.reserve(results().size());

			for (size_t i = 0; i < results().size(); ++i) {
				Result result = result_at<Result>(i);
				if (convert(result))
					res.push_back(result);
			}

			if (res.empty()) {
				try {
					if (has_id)
						throw_error(-ENOENT, id, "Failed to request statistics");
					else
						throw_error(-ENOENT, "Failed to request statistics");
				} catch (...) {
					exc = std::current_exception();
				}
				handler(exc);
			} else {
				handler(res);
			}
		}

		virtual bool convert(Result &result) = 0;

		dnet_commands command;
		session sess;
		std::function<void (const array_result_holder<Result> &)> handler;
		dnet_id id;
		bool has_id;
};

class stat_callback : public base_stat_callback<stat_result_entry, DNET_CMD_STAT>
{
	public:
		typedef std::shared_ptr<stat_callback> ptr;

		stat_callback(const session &sess)
		: base_stat_callback<stat_result_entry, DNET_CMD_STAT>(sess)
		{
		}

		bool convert(stat_result_entry &result)
		{
			if (result.size() < sizeof(struct dnet_stat))
				return false;
			dnet_convert_stat(result.statistics());
			return true;
		}
};

class stat_count_callback : public base_stat_callback<stat_count_result_entry, DNET_CMD_STAT_COUNT>
{
	public:
		typedef std::shared_ptr<stat_count_callback> ptr;

		stat_count_callback(const session &sess)
		: base_stat_callback<stat_count_result_entry, DNET_CMD_STAT_COUNT>(sess)
		{
		}

		bool convert(stat_count_result_entry &result)
		{
			if (result.size() <= sizeof(struct dnet_addr_stat))
				return false;
			dnet_convert_addr_stat(result.statistics(), 0);
			return true;
		}
};

class multigroup_callback
{
	public:
		multigroup_callback(const session &sess) : sess(sess), m_group_index(0)
		{
		}

		/*
		 * Method is called by several ways:
		 * 1. From the same thread as iterate_groups, in that case it's guaranteed
		 * cb.handle to return false as cb::count is set to unlimited.
		 * 2. From the i/o thread, then guaranteed that it's different from
		 * iterate_groups's thread, so lock can't be dead one.
		 */
		bool handle(struct dnet_net_state *state, struct dnet_cmd *cmd, complete_func func, void *priv)
		{
			if (cb.handle(state, cmd, func, priv)) {
				// cb has ended it's work
				if (check_answer()) {
					// correct answer is found
					return true;
				} else {
					return iterate_groups(func, priv);
				}
			}
			return false;
		}

		/*
		 * Iterates through groups, it must be guaranteed that each thread
		 * doesn't invoke this method recursivly.
		 */
		bool iterate_groups(complete_func func, void *priv)
		{
			std::lock_guard<std::mutex> lock(m_mutex);
			// try next group
			while (m_group_index < groups.size()) {
				try {
					struct dnet_id id = kid.id();
					id.group_id = groups[m_group_index];
					++m_group_index;
					if (next_group(id, func, priv)) {
						// all replies are received
						if (check_answer()) {
							// and information is ready
							return true;
						} else {
							// but we need more data
							continue;
						}
					}
					// request is sent, wait results
					return false;
				} catch (std::exception &e) {
					// some exception, log and try next group
					if (kid.by_id()) {
						dnet_log_raw(sess.get_node().get_native(),
							DNET_LOG_ERROR,
							"%s: %s\n",
							dnet_dump_id(&kid.id()),
							e.what());
					} else {
						dnet_log_raw(sess.get_node().get_native(),
							DNET_LOG_ERROR,
							"%s: %s : %s\n",
							dnet_dump_id(&kid.id()),
							e.what(),
							kid.remote().c_str());
					}
				}
			}
			// there is no success :(
			notify_about_error();
			throw_error(-ENOENT, kid, "Something happened wrong");
			return false;
		}

		bool start(complete_func func, void *priv)
		{
			return iterate_groups(func, priv);
		}

		virtual bool check_answer()
		{
			return cb.is_valid();
		}

		/*
		 * Sends requests for current id.
		 *
		 * Returnes true, if all requests are completed, returnes false otherwise.
		 */
		virtual bool next_group(dnet_id &id, complete_func func, void *priv) = 0;

		virtual void finish(std::exception_ptr exc) = 0;

		virtual void notify_about_error() = 0;

		session sess;
		default_callback cb;
		key kid;
		std::vector<int> groups;

	protected:
		std::mutex m_mutex;
		size_t m_group_index;
};

class lookup_callback : public multigroup_callback
{
	public:
		typedef std::shared_ptr<lookup_callback> ptr;

		lookup_callback(const session &sess) : multigroup_callback(sess)
		{
		}

		bool next_group(dnet_id &id, complete_func func, void *priv)
		{
			cb.clear();
			cb.set_count(unlimited);

			int err = dnet_lookup_object(sess.get_native(), &id, func, priv);
			if (err) {
				throw_error(err, kid, "Failed to lookup ID");
			}

			return cb.set_count(1);
		}

		void finish(std::exception_ptr exc)
		{
			if (exc != std::exception_ptr()) {
				handler(exc);
			} else {
				lookup_result_entry result = cb.any_result<lookup_result_entry>();
				dnet_convert_addr(result.storage_address());
				dnet_convert_file_info(result.file_info());
				handler(result);
			}
		}

		void notify_about_error()
		{
			throw_error(-ENOENT, kid, "Failed to lookup ID");
		}

		std::function<void (const lookup_result &)> handler;
};

class read_callback : public multigroup_callback
{
	public:
		typedef std::shared_ptr<read_callback> ptr;

		read_callback(const session &sess, const dnet_io_control &ctl)
			: multigroup_callback(sess), ctl(ctl)
		{
		}

		bool next_group(dnet_id &id, complete_func func, void *priv)
		{
			cb.clear();
			cb.set_count(unlimited);

			memcpy(&ctl.id, &id, sizeof(id));
			ctl.complete = func;
			ctl.priv = priv;
			int err = dnet_read_object(sess.get_native(), &ctl);
			if (err) {
				throw_error(err, ctl.id, "READ: size: %llu",
					static_cast<unsigned long long>(ctl.io.size));
			}

			return cb.set_count(1);
		}

		void finish(std::exception_ptr exc)
		{
			if (exc != std::exception_ptr()) {
				handler(exc);
			} else {
				std::vector<read_result_entry> results;
				results.reserve(cb.results_size());
				for (size_t i = 0; i < cb.results_size(); ++i) {
					read_result_entry result = cb.result_at<read_result_entry>(i);
					if (result.size() >= sizeof(struct dnet_io_attr)) {
						dnet_convert_io_attr(result.io_attribute());
						results.push_back(result);
					}
				}
				if (results.empty()) {
					try {
						notify_about_error();
					} catch (...) {
						exc = std::current_exception();
					}
					handler(exc);
				} else {
					handler(results);
				}
			}
		}

		void notify_about_error()
		{
			throw_error(-ENOENT, ctl.id, "READ: size: %llu",
				static_cast<unsigned long long>(ctl.io.size));
		}

		struct dnet_io_control ctl;
		std::function<void (const read_results &)> handler;
};

struct io_attr_comparator
{
	bool operator() (const dnet_io_attr &io1, const dnet_io_attr &io2)
	{
		return memcmp(io1.id, io2.id, DNET_ID_SIZE) < 0;
	}
};

typedef std::set<dnet_io_attr, io_attr_comparator> io_attr_set;

#define debug(DATA) if (1) {} else std::cerr << __PRETTY_FUNCTION__ << ":" << __LINE__ << " " << DATA << std::endl

class read_bulk_callback : public read_callback
{
	public:
		typedef std::shared_ptr<read_bulk_callback> ptr;

		read_bulk_callback(const session &sess, const io_attr_set &ios, const dnet_io_control &ctl)
			: read_callback(sess, ctl), ios_set(ios)
		{
		}

		bool next_group(dnet_id &id, complete_func func, void *priv)
		{
			cb.clear();
			cb.set_count(unlimited);

			debug(m_group_index);
			int count = 0;

			try {
				ios_cache.assign(ios_set.begin(), ios_set.end());
				const size_t io_num = ios_cache.size();
				dnet_io_attr *ios = ios_cache.data();

				dnet_node *node = sess.get_node().get_native();
				dnet_net_state *cur, *next = NULL;
				dnet_id next_id = id;
				const int group_id = id.group_id;
				int start = 0;

				dnet_setup_id(&id, group_id, ios[0].id);
				id.type = ios[0].type;

				debug("");

				cur = dnet_state_get_first(node, &id);
				if (!cur)
					throw_error(-ENOENT, id, "Can't get state for id");

				for (size_t i = 0; i < io_num; ++i) {
					debug("i = " << i);
					if ((i + 1) < io_num) {
						dnet_setup_id(&next_id, group_id, ios[i + 1].id);
						next_id.type = ios[i + 1].type;

						next = dnet_state_get_first(node, &next_id);
						if (!next)
							throw_error(-ENOENT, next_id, "Can't get state for id");

						/* Send command only if state changes or it's a last id */
						if ((cur == next)) {
							dnet_state_put(next);
							next = NULL;
							continue;
						}
					}
					debug("");

					dnet_log_raw(sess.get_node().get_native(),
						DNET_LOG_NOTICE, "start: %s: end: %s, count: %llu, addr: %s\n",
						dnet_dump_id(&id),
						dnet_dump_id(&next_id),
						(unsigned long long)(i - start),
						dnet_state_dump_addr(cur));

					ctl.io.size = (i - start + 1) * sizeof(struct dnet_io_attr);
					ctl.data = ios + start;

					memcpy(&ctl.id, &id, sizeof(id));
					ctl.complete = func;
					ctl.priv = priv;

					++count;

					int err = dnet_read_object(sess.get_native(), &ctl);
					// ingore the error, we must continue :)
					(void) err;
					debug("err = " << err);

					start = i + 1;
					dnet_state_put(cur);
					cur = next;
					next = NULL;
					memcpy(&id, &next_id, sizeof(struct dnet_id));
				}
			} catch (error &e) {
				debug("exception: " << e.what());
				debug("count: " << count);
				if (cb.set_count(count))
					throw;
			} catch (...) {
				debug("unknown exception");
				debug("count: " << count);
				if (cb.set_count(count))
					throw;
			}

			debug("count: " << count);
			return cb.set_count(count);
		}

		bool check_answer()
		{
			elliptics_assert(cb.is_ready());
			debug("cb.is_valid() " << cb.is_valid());

			if (cb.is_valid()) {
				debug("cb.results_size() " << cb.results_size());
				debug("before: ios_set.size() " << ios_set.size());
				for (size_t i = 0; i < cb.results_size(); ++i) {
					read_result_entry entry = cb.result_at<read_result_entry>(i);
					if (entry.size() < sizeof(struct dnet_io_attr))
						continue;
					result.push_back(entry);
					ios_set.erase(*entry.io_attribute());
				}
				debug("after: ios_set.size() " << ios_set.size());
			}

			debug("ios_set.empty() " << ios_set.empty());
			debug("m_group_index == groups.size() " << (m_group_index == groups.size()));
			// all results are found or all groups are iterated
			return ios_set.empty() || (m_group_index == groups.size());
		}

		void finish(std::exception_ptr exc)
		{
			debug("finish");
			if (!result.empty()) {
				handler(result);
			} else {
				handler(exc);
			}
		}

		void notify_about_error()
		{
			throw_error(-ENOENT, "bulk_read: can't read data");
		}

		io_attr_set ios_set;
		std::vector<dnet_io_attr> ios_cache;
		std::vector<read_result_entry> result;
};

class cmd_callback : public default_callback
{
	public:
		typedef std::shared_ptr<cmd_callback> ptr;

		cmd_callback(const session &sess, const transport_control &ctl) : sess(sess), ctl(ctl.get_native())
		{
		}

		bool start(complete_func func, void *priv)
		{
			set_count(unlimited);
			ctl.complete = func;
			ctl.priv = priv;

			int err = dnet_request_cmd(sess.get_native(), &ctl);
			if (err < 0) {
				throw_error(err, "failed to request cmd: %s", dnet_cmd_string(ctl.cmd));
			}

			return set_count(err);
		}

		void finish(std::exception_ptr exc)
		{
			if (exc != std::exception_ptr())
				handler(exc);
			else
				handler(results());
		}

		session sess;
		dnet_trans_control ctl;
		std::function<void (const command_result &)> handler;
};

class prepare_latest_callback : public default_callback
{
	public:
		typedef std::shared_ptr<prepare_latest_callback> ptr;

		class entry
		{
			public:
				struct dnet_id *id;
				struct dnet_file_info *fi;

				bool operator <(const entry &other) const
				{
					return (fi->mtime.tsec > other.fi->mtime.tsec)
						|| (fi->mtime.tsec == other.fi->mtime.tsec
							&& (fi->mtime.tnsec > other.fi->mtime.tnsec));
				}

				bool operator ==(const entry &other) const
				{
					return fi->mtime.tsec == other.fi->mtime.tsec
						&& fi->mtime.tnsec == other.fi->mtime.tnsec;
				}
		};

		prepare_latest_callback(const session &sess, const std::vector<int> &groups) : sess(sess), groups(groups)
		{
		}

		bool start(complete_func func, void *priv)
		{
			set_count(unlimited);

			uint64_t cflags_pop = sess.get_cflags();
			sess.set_cflags(sess.get_cflags() | DNET_ATTR_META_TIMES);

			dnet_id raw = id.id();
			for (size_t i = 0; i < groups.size(); ++i) {
				raw.group_id = groups[i];
				dnet_lookup_object(sess.get_native(), &raw, func, priv);
			}

			sess.set_cflags(cflags_pop);
			return set_count(groups.size());
		}

		void finish(std::exception_ptr exc)
		{
			if (exc != std::exception_ptr()) {
				handler(exc);
			}

			std::vector<entry> entries;
			for (size_t i = 0; i < results_size(); ++i) {
				const lookup_result_entry &le = result_at<lookup_result_entry>(i);
				if (le.size() < sizeof(struct dnet_addr) + sizeof(struct dnet_file_info))
					continue;
				entry e = { &le.command()->id, le.file_info() };
				entries.push_back(e);
			}

			std::sort(entries.begin(), entries.end());

			for (size_t i = 1; i < entries.size(); ++i) {
				if (entries[i].id->group_id == group_id	&& entries[i] == entries[0]) {
					std::swap(entries[i], entries[0]);
					break;
				}
			}

			std::vector<int> result(entries.size());
			for (size_t i = 0; i < entries.size(); ++i)
				result[i] = entries[i].id->group_id;

			handler(result);
		}

		session sess;
		const std::vector<int> &groups;
		key id;
		uint32_t group_id;
		std::function<void (const prepare_latest_result &)> handler;
};

class write_callback : public default_callback
{
	public:
		typedef std::shared_ptr<write_callback> ptr;

		write_callback(const session &sess, const dnet_io_control &ctl) : sess(sess), ctl(ctl)
		{
		}

		bool start(complete_func func, void *priv)
		{
			ctl.complete = func;
			ctl.priv = priv;
			set_count(unlimited);

			int err = dnet_write_object(sess.get_native(), &ctl);
			if (err < 0) {
				throw_error(err, "Failed to write data");
				return false;
			} else {
				return set_count(err);
			}
		}

		void finish(std::exception_ptr exc)
		{
			if (exc != std::exception_ptr()) {
				handler(exc);
				return;
			}

			std::vector<write_result_entry> results;
			results.reserve(results_size());
			for (size_t i = 0; i < results_size(); ++i) {
				write_result_entry result = result_at<write_result_entry>(i);
				/*
				 * '=' part in '>=' comparison here means backend does not provide information about filename,
				 * where given object is stored.
				 */
				if (result.size() >= sizeof(struct dnet_addr) + sizeof(struct dnet_file_info)) {
					dnet_convert_addr(result.storage_address());
					dnet_convert_file_info(result.file_info());
					results.push_back(result);
				}
			}
			handler(results);
		}

		session sess;
		dnet_io_control ctl;
		std::function<void (const write_result &)> handler;
};

class remove_callback : public default_callback
{
	public:
		typedef std::shared_ptr<remove_callback> ptr;

		remove_callback(const session &sess, const dnet_id &id)
			: sess(sess), id(id)
		{
		}

		bool start(complete_func func, void *priv)
		{
			set_count(unlimited);

			const auto &sess_groups = sess.get_groups();
			std::copy(sess_groups.begin(), sess_groups.end(),
				std::inserter(groups, groups.begin()));

			uint64_t cflags_pop = sess.get_cflags();
			sess.set_cflags(cflags_pop | DNET_ATTR_DELETE_HISTORY);
			int err = dnet_remove_object(sess.get_native(), &id,
				func, priv);
			sess.set_cflags(cflags_pop);

			if (err < 0) {
				throw_error(err, id, "REMOVE");
				return false;
			} else {
				return set_count(err);
			}
		}

		void finish(std::exception_ptr exc)
		{
			if (exc != std::exception_ptr()) {
				handler(exc);
				return;
			}

			for (size_t i = 0; i < results_size(); ++i) {
				const callback_result_entry &entry = result_at(i);
				dnet_cmd *cmd = entry.command();
				if (cmd->status < 0)
					groups.erase(cmd->id.group_id);
			}

			if (groups.empty()) {
				try {
					throw_error(-ENOENT, id, "REMOVE");
				} catch (...) {
					handler(std::current_exception());
					return;
				}
			}
			handler(exc);
		}

		session sess;
		std::set<int> groups;
		dnet_id id;
		std::function<void (const std::exception_ptr &)> handler;
};

class exec_result_data : public callback_result_data
{
	public:
		exec_context context;
};

class exec_callback : public default_callback
{
	public:
		typedef std::shared_ptr<exec_callback> ptr;

		exec_callback(const session &sess) : sess(sess), id(NULL), sph(NULL)
		{
		}

		bool start(complete_func func, void *priv)
		{
			set_count(unlimited);

			int err = dnet_send_cmd(sess.get_native(), id, func, priv, sph);
			if (err < 0) {
				char buffer[128];
				strncpy(buffer, sph->data, std::min<size_t>(sizeof(buffer), sph->event_size));
				buffer[sizeof(buffer) - 1] = '\0';
				throw_error(err, "failed to execute cmd: %s", buffer);
			}

			return set_count(err);
		}


		virtual void process(struct dnet_cmd *cmd, const callback_result_data &generic_data)
		{
			// this method is run only inside mutex lock
			auto data = std::make_shared<exec_result_data>();
			exec_result_entry entry(data);
			data->data = generic_data.data;
			if (cmd->status) {
				data->error = create_error(cmd->status, cmd->id, "Failed to process execution request");
			} else {
				if (!entry.data().empty())
					data->context = exec_context::parse(entry.data(), &data->error);
			}

			// TODO: Remove exception handling from internal callbacks
			// If there is no try/catch block we get memory corruption instead of abort in case of exception
			try {
				handler(entry);
			} catch (const std::exception &exc) {
				dnet_log_raw(sess.get_node().get_native(),
					DNET_LOG_ERROR,
					"UNCAUGHT ASYNC EXCEPTION: %s",
					exc.what());
				abort();
			} catch (...) {
				dnet_log_raw(sess.get_node().get_native(),
					DNET_LOG_ERROR,
					"UNCAUGHT ASYNC EXCEPTION");
				abort();
			}
		}

		void finish(std::exception_ptr exc)
		{
			if (complete_handler)
				complete_handler(exc);
		}

		session sess;
		struct dnet_id *id;
		struct sph *sph;
		std::function<void (const exec_result &)> handler;
		std::function<void (const std::exception_ptr &)> complete_handler;
};

class iterator_callback : public default_callback
{
	public:
		typedef std::shared_ptr<iterator_callback> ptr;

		iterator_callback(const session &sess) : sess(sess)
		{
		}

		bool start(complete_func func, void *priv)
		{
			set_count(unlimited);

			dnet_trans_control ctl;
			memset(&ctl, 0, sizeof(ctl));
			memcpy(&ctl.id, &id, sizeof(id));
			ctl.id.group_id = sess.get_groups().front();
			ctl.cflags = sess.get_cflags() | DNET_FLAGS_NEED_ACK;
			ctl.cmd = DNET_CMD_ITERATOR;
			ctl.complete = func;
			ctl.priv = priv;

			dnet_convert_iterator_request(&request);
			ctl.data = &request;
			ctl.size = sizeof(request);

			int err = dnet_trans_alloc_send(sess.get_native(), &ctl);
			if (err < 0) {
				throw_error(err, "failed to start iterator");
			}

			return set_count(1);
		}


		virtual void process(struct dnet_cmd *cmd, const callback_result_data &generic_data)
		{
			// this method is run only inside mutex lock
			auto data = std::make_shared<callback_result_data>(generic_data);
			data->data = generic_data.data;
			if (cmd->status) {
				data->error = create_error(cmd->status, cmd->id, "Failed to process execution request");
			}

			// TODO: Remove exception handling from internal callbacks
			// If there is no try/catch block we get memory corruption instead of abort in case of exception
			try {
				callback_result_entry entry(data);
				handler(*reinterpret_cast<iterator_result_entry*>(&entry));
			} catch (const std::exception &exc) {
				dnet_log_raw(sess.get_node().get_native(),
					DNET_LOG_ERROR,
					"UNCAUGHT ASYNC EXCEPTION: %s",
					exc.what());
				abort();
			} catch (...) {
				dnet_log_raw(sess.get_node().get_native(),
					DNET_LOG_ERROR,
					"UNCAUGHT ASYNC EXCEPTION");
				abort();
			}
		}

		void finish(std::exception_ptr exc)
		{
			if (complete_handler)
				complete_handler(exc);
		}

		session sess;
		struct dnet_id id;
		dnet_iterator_request request;
		std::function<void (const iterator_result &)> handler;
		std::function<void (const std::exception_ptr &)> complete_handler;
};

extern std::set<void*> &assertion_callback_set();
extern std::mutex &assertion_callback_mutex();

template <typename T>
inline bool assertion_callback_insert(std::shared_ptr<T> *cb)
{
	fprintf(stderr, "START: %p, %s\n", cb, __ASSERT_FUNCTION);
	fflush(stderr);
	assertion_callback_mutex().lock();
	bool result = assertion_callback_set().insert(cb).second;
	assertion_callback_mutex().unlock();
	return result;
}

template <typename T>
inline bool assertion_callback_find(std::shared_ptr<T> *cb)
{
	fprintf(stderr, "FIND: %p, %s\n", cb, __ASSERT_FUNCTION);
	fflush(stderr);
	assertion_callback_mutex().lock();
	bool result = assertion_callback_set().find(cb) != assertion_callback_set().end();
	assertion_callback_mutex().unlock();
	return result;
}

template <typename T>
inline bool assertion_callback_remove(std::shared_ptr<T> *cb)
{
	fprintf(stderr, "REMOVE: %p, %s\n", cb, __ASSERT_FUNCTION);
	fflush(stderr);
	assertion_callback_mutex().lock();
	bool result = (assertion_callback_set().erase(cb) == 1);
	assertion_callback_mutex().unlock();
	return result;
}

template <typename T>
struct dnet_style_handler
{
	static std::set<std::shared_ptr<T> *> privs;

	static int handler(struct dnet_net_state *state, struct dnet_cmd *cmd, void *priv)
	{
		std::shared_ptr<T> &ptr = *reinterpret_cast<std::shared_ptr<T> *>(priv);
		elliptics_assert(assertion_callback_find(&ptr));

		bool isFinished = false;
		std::exception_ptr exc_ptr;
		try {
			isFinished = ptr->handle(state, cmd, handler, priv);
		} catch (...) {
			exc_ptr = std::current_exception();
			isFinished = true;
		}

		if (isFinished)
			finish(ptr, exc_ptr);
		return 0;
	}

	static void start(const std::shared_ptr<T> &cb)
	{
		std::shared_ptr<T> *cb_ptr = new std::shared_ptr<T>(cb);

		elliptics_assert(assertion_callback_insert(cb_ptr));

		bool result = false;

		try {
			result = cb->start(handler, cb_ptr);
		} catch (...) {
			finish(*cb_ptr, std::current_exception());
		}

		if (result)
			finish(*cb_ptr, std::exception_ptr());
	}

	static void finish(std::shared_ptr<T> &cb, const std::exception_ptr &exc)
	{
		elliptics_assert(assertion_callback_remove(&cb));

		try {
			cb->finish(exc);
		} catch (const std::exception &exc) {
			dnet_log_raw(cb->sess.get_node().get_native(),
				DNET_LOG_ERROR,
				"UNCAUGHT ASYNC EXCEPTION: %s",
				exc.what());
			abort();
		} catch (...) {
			dnet_log_raw(cb->sess.get_node().get_native(),
				DNET_LOG_ERROR,
				"UNCAUGHT ASYNC EXCEPTION");
			abort();
		}
		delete &cb;
	}
};

template <typename T>
static inline void startCallback(const std::shared_ptr<T> &cb)
{
	dnet_style_handler<T>::start(cb);
}

} } // namespace ioremap::elliptics

#endif // CALLBACK_P_H
