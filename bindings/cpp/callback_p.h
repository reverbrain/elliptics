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

#include "elliptics/cppdef.h"

#include <exception>
#include <set>
#include <thread>
#include <mutex>
#include <condition_variable>
#include <algorithm>
#include <cassert>
#include <iostream>

//#ifdef DEVELOPER_BUILD
//#  define elliptics_assert(expr) assert(expr)
//#else
#  define elliptics_assert(expr)
//#endif

namespace ioremap { namespace elliptics {

class session_scope
{
	public:
		session_scope(session &sess) : m_sess(sess)
		{
			m_filter = m_sess.get_filter();
			m_checker = m_sess.get_checker();
			m_policy = m_sess.get_exceptions_policy();
			m_cflags = m_sess.get_cflags();
			m_ioflags = m_sess.get_ioflags();
		}

		~session_scope()
		{
			m_sess.set_filter(m_filter);
			m_sess.set_checker(m_checker);
			m_sess.set_exceptions_policy(m_policy);
			m_sess.set_cflags(m_cflags);
			m_sess.set_ioflags(m_ioflags);
		}

	private:
		session &m_sess;
		result_filter m_filter;
		result_checker m_checker;
		uint64_t m_cflags;
		uint32_t m_ioflags;
		uint32_t m_policy;
};

typedef int (*complete_func)(struct dnet_net_state *, struct dnet_cmd *, void *);

class callback_result_data
{
	public:
		callback_result_data()
		{
		}

		callback_result_data(dnet_addr *addr, dnet_cmd *cmd)
		{
			const size_t size = sizeof(struct dnet_addr) + sizeof(struct dnet_cmd) + cmd->size;
			void *allocated = malloc(size);
			if (!allocated)
				throw std::bad_alloc();
			data = data_pointer(allocated, size);
			memcpy(data.data(), addr, sizeof(struct dnet_addr));
			memcpy(data.data<char>() + sizeof(struct dnet_addr), cmd, sizeof(struct dnet_cmd) + cmd->size);
		}

		virtual ~callback_result_data()
		{
		}

		data_pointer data;
		error_info error;
		exec_context context;
};

enum special_count { unlimited };

struct entry_converter
{
	static void convert(exec_result_entry &entry, callback_result_data *data)
	{
		data->context = exec_context::parse(entry.data(), &data->error);
	}

	static void convert(iterator_result_entry &entry, callback_result_data *)
	{
		dnet_convert_iterator_response(entry.reply());
	}

	static void convert(lookup_result_entry &entry, callback_result_data *)
	{
		dnet_convert_addr(entry.storage_address());
		dnet_convert_file_info(entry.file_info());
	}

	static void convert(read_result_entry &entry, callback_result_data *)
	{
		dnet_convert_io_attr(entry.io_attribute());
	}

	static void convert(stat_result_entry &entry, callback_result_data *)
	{
		dnet_convert_stat(entry.statistics());
	}

	static void convert(stat_count_result_entry &entry, callback_result_data *)
	{
		dnet_convert_addr_stat(entry.statistics(), 0);
	}

	static void convert(callback_result_entry &, callback_result_data *)
	{
	}
};

template <typename T>
class default_callback
{
	public:
		default_callback(const async_result<T> &result) : m_count(1), m_complete(0), m_result(result)
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

		void set_total(size_t total)
		{
			m_result.set_total(total);
		}

		size_t get_total() const
		{
			return m_result.get_total();
		}

		bool handle(struct dnet_net_state *state, struct dnet_cmd *cmd, complete_func, void *)
		{
			std::lock_guard<std::mutex> lock(m_mutex);

			if (is_trans_destroyed(state, cmd)) {
				++m_complete;
			} else {
				if (!(cmd->flags & DNET_FLAGS_MORE))
					m_statuses.push_back(cmd->status);
				auto data = std::make_shared<callback_result_data>(dnet_state_addr(state), cmd);
				process(cmd, data, data.get());
			}
			return (m_count == m_complete);
		}

		void process(dnet_cmd *cmd, const callback_result_entry &default_entry, callback_result_data *data)
		{
			T entry = *static_cast<const T *>(&default_entry);
			if (cmd->status) {
				data->error = create_error(*cmd);
			}
			if (!entry.data().empty())
				entry_converter::convert(entry, data);
			m_result.process(entry);
		}

		bool is_ready()
		{
			std::lock_guard<std::mutex> lock(m_mutex);
			return (m_count == m_complete);
		}

		bool is_valid() const
		{
			bool ok = false;
			for (size_t i = 0; i < m_statuses.size(); ++i)
				ok |= (m_statuses[i] == 0);
			return ok;
		}

		const std::vector<int> &statuses() const
		{
			return m_statuses;
		}

		void clear()
		{
			m_complete = 0;
			m_statuses.clear();
		}

		void complete(std::exception_ptr exc)
		{
			if (exc) {
				try {
					std::rethrow_exception(exc);
				} catch (error &e) {
					m_result.complete(error_info(e.error_code(), e.error_message()));
				} catch (std::bad_alloc &) {
					m_result.complete(error_info(-ENOMEM, std::string()));
				}
			} else {
				m_result.complete(error_info());
			}
		}

		void complete(const error_info &error)
		{
			m_result.complete(error);
		}

	protected:
		size_t m_count;
		size_t m_complete;
		std::vector<int> m_statuses;
		std::mutex m_mutex;
		typename async_result<T>::handler m_result;
};

template <typename Result, dnet_commands Command>
class base_stat_callback
{
	public:
		base_stat_callback(const session &sess, const async_result<Result> &result)
			: sess(sess), cb(result), has_id(false)
		{
		}

		virtual ~base_stat_callback()
		{
		}

		bool start(error_info *error, complete_func func, void *priv)
		{
			cb.set_count(unlimited);

			uint64_t cflags_pop = sess.get_cflags();
			sess.set_cflags(cflags_pop | DNET_ATTR_CNTR_GLOBAL);
			int err = dnet_request_stat(sess.get_native(),
				has_id ? &id : NULL, Command, func, priv);
			sess.set_cflags(cflags_pop);

			if (err < 0) {
				*error = create_error(err, "Failed to request statistics");
				return true;
			}

			return cb.set_count(err);
		}

		bool handle(error_info *error, dnet_net_state *state, dnet_cmd *cmd, complete_func func, void *priv)
		{
			(void) error;
			return cb.handle(state, cmd, func, priv);
		}

		void finish(const error_info &exc)
		{
			cb.complete(exc);
		}

		dnet_commands command;
		session sess;
		default_callback<Result> cb;
		dnet_id id;
		bool has_id;
};

class stat_callback : public base_stat_callback<stat_result_entry, DNET_CMD_STAT>
{
	public:
		typedef std::shared_ptr<stat_callback> ptr;

		stat_callback(const session &sess, const async_stat_result &result)
			: base_stat_callback<stat_result_entry, DNET_CMD_STAT>(sess, result)
		{
		}
};

class stat_count_callback : public base_stat_callback<stat_count_result_entry, DNET_CMD_STAT_COUNT>
{
	public:
		typedef std::shared_ptr<stat_count_callback> ptr;

		stat_count_callback(const session &sess, const async_stat_count_result &result)
			: base_stat_callback<stat_count_result_entry, DNET_CMD_STAT_COUNT>(sess, result)
		{
		}
};

template <typename T>
class multigroup_callback
{
	public:
		multigroup_callback(const session &sess, const async_result<T> &result)
			: sess(sess), cb(result), m_group_index(0)
		{
		}

		virtual ~multigroup_callback()
		{
		}

		/*
		 * Method is called by several ways:
		 * 1. From the same thread as iterate_groups, in that case it's guaranteed
		 * cb.handle to return false as cb::count is set to unlimited.
		 * 2. From the i/o thread, then guaranteed that it's different from
		 * iterate_groups's thread, so lock can't be dead one.
		 */
		bool handle(error_info *error, struct dnet_net_state *state, struct dnet_cmd *cmd, complete_func func, void *priv)
		{
			if (cb.handle(state, cmd, func, priv)) {
				// cb has ended it's work
				if (check_answer()) {
					// correct answer is found
					return true;
				} else {
					return iterate_groups(error, func, priv);
				}
			}
			return false;
		}

		/*
		 * Iterates through groups, it must be guaranteed that each thread
		 * doesn't invoke this method recursivly.
		 */
		bool iterate_groups(error_info *error, complete_func func, void *priv)
		{
			std::lock_guard<std::mutex> lock(m_mutex);
			// try next group
			while (m_group_index < groups.size()) {
				struct dnet_id id = kid.id();
				id.group_id = groups[m_group_index];

				++m_group_index;
				if (next_group(error, id, func, priv)) {
					if (error->code()) {
						// some exception, log and try next group
						dnet_log_raw(sess.get_node().get_native(),
							DNET_LOG_NOTICE,
							"%s\n",
							error->message().c_str());
						*error = error_info();
						continue;
					}
					// all replies are received
					if (check_answer()) {
						// and there is error or information is ready
						return true;
					} else {
						// but we need more data
						continue;
					}
				}
				// request is sent, wait results
				return false;
			}
			// there is no success :(
			*error = prepare_error();
			return true;
		}

		bool start(error_info *error, complete_func func, void *priv)
		{
			return iterate_groups(error, func, priv);
		}

		void finish(const error_info &error)
		{
			cb.complete(error);
		}

		virtual bool check_answer()
		{
			return cb.is_valid();
		}

		/*
		 * Sends requests for current id.
		 *
		 * Returns true, if all requests are completed, returns false otherwise.
		 */
		virtual bool next_group(error_info *error, dnet_id &id, complete_func func, void *priv) = 0;

		virtual error_info prepare_error() = 0;

		session sess;
		default_callback<T> cb;
		key kid;
		std::vector<int> groups;

	protected:
		std::mutex m_mutex;
		size_t m_group_index;
};

class lookup_callback : public multigroup_callback<lookup_result_entry>
{
	public:
		typedef std::shared_ptr<lookup_callback> ptr;

		lookup_callback(const session &sess, const async_lookup_result &result)
			: multigroup_callback<lookup_result_entry>(sess, result)
		{
			cb.set_total(1);
		}

		bool next_group(error_info *error, dnet_id &id, complete_func func, void *priv)
		{
			cb.clear();
			cb.set_count(unlimited);

			int err = dnet_lookup_object(sess.get_native(), &id, func, priv);
			if (err) {
				*error = create_error(err, kid, "Failed to lookup ID");
				// Try next group
				return true;
			}

			return cb.set_count(1);
		}

		error_info prepare_error()
		{
			return create_error(-ENOENT, kid, "Failed to lookup ID");
		}
};

class read_callback : public multigroup_callback<read_result_entry>
{
	public:
		typedef std::shared_ptr<read_callback> ptr;

		read_callback(const session &sess, const async_read_result &result, const dnet_io_control &ctl)
			: multigroup_callback<read_result_entry>(sess, result), ctl(ctl)
		{
		}

		bool next_group(error_info *error, dnet_id &id, complete_func func, void *priv)
		{
			cb.clear();
			cb.set_count(unlimited);

			memcpy(&ctl.id, &id, sizeof(id));
			ctl.complete = func;
			ctl.priv = priv;

			int err = dnet_read_object(sess.get_native(), &ctl);
			if (err) {
				*error = create_error(err, ctl.id, "READ: size: %llu",
					static_cast<unsigned long long>(ctl.io.size));
				return true;
			}

			return cb.set_count(1);
		}

		void finish(const error_info &error)
		{
			cb.complete(error);
		}

		error_info prepare_error()
		{
			return create_error(-ENOENT, ctl.id, "READ: size: %llu",
				static_cast<unsigned long long>(ctl.io.size));
		}

		struct dnet_io_control ctl;
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

		read_bulk_callback(const session &sess, const async_read_result &result, const io_attr_set &ios, const dnet_io_control &ctl)
			: read_callback(sess, result, ctl), ios_set(ios)
		{
		}

		bool handle(error_info *error, struct dnet_net_state *state, struct dnet_cmd *cmd, complete_func func, void *priv)
		{
			// Remove from ios_set entries for which result is ready
			if (cmd->status == 0 && cmd->size >= sizeof(dnet_io_attr)) {
				std::lock_guard<std::mutex> lock(ios_set_mutex);
				dnet_io_attr &attr = *reinterpret_cast<dnet_io_attr*>(cmd + 1);
				ios_set.erase(attr);
			}
			return read_callback::handle(error, state, cmd, func, priv);
		}

		bool next_group(error_info *error, dnet_id &id, complete_func func, void *priv)
		{
			cb.clear();
			cb.set_count(unlimited);

			debug(m_group_index);
			int count = 0;

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
			if (!cur) {
				*error = create_error(-ENOENT, id, "Can't get state for id");
				return true;
			}

			for (size_t i = 0; i < io_num; ++i) {
				debug("i = " << i);
				if ((i + 1) < io_num) {
					dnet_setup_id(&next_id, group_id, ios[i + 1].id);
					next_id.type = ios[i + 1].type;

					next = dnet_state_get_first(node, &next_id);
					if (!next) {
						*error = create_error(-ENOENT, next_id, "Can't get state for id");
						if (cb.set_count(count))
							return true;
						return false;
					}

					/* Send command only if state changes or it's a last id */
					if (cur == next) {
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

			debug("count: " << count);
			return cb.set_count(count);
		}

		bool check_answer()
		{
			elliptics_assert(cb.is_ready());
			debug("cb.is_valid() " << cb.is_valid());

//			if (cb.is_valid()) {
//				debug("cb.results_size() " << cb.results_size());
//				debug("before: ios_set.size() " << ios_set.size());
//				for (size_t i = 0; i < cb.results_size(); ++i) {
//					read_result_entry entry = cb.result_at<read_result_entry>(i);
//					if (entry.size() < sizeof(struct dnet_io_attr))
//						continue;
//					result.push_back(entry);
//					ios_set.erase(*entry.io_attribute());
//				}
//				debug("after: ios_set.size() " << ios_set.size());
//			}

			debug("ios_set.empty() " << ios_set.empty());
			debug("m_group_index == groups.size() " << (m_group_index == groups.size()));
			// all results are found or all groups are iterated
			return ios_set.empty() || (m_group_index == groups.size());
		}

		void finish(const error_info &exc)
		{
			debug("finish");
			cb.complete(exc);
		}

		error_info prepare_error()
		{
			return create_error(-ENOENT, "bulk_read: can't read data");
		}

		std::mutex ios_set_mutex;
		io_attr_set ios_set;
		std::vector<dnet_io_attr> ios_cache;
		std::vector<read_result_entry> result;
};

class cmd_callback
{
	public:
		typedef std::shared_ptr<cmd_callback> ptr;

		cmd_callback(const session &sess, const async_generic_result &result, const transport_control &ctl)
			: sess(sess), ctl(ctl.get_native()), cb(result)
		{
		}

		bool start(error_info *error, complete_func func, void *priv)
		{
			cb.set_count(unlimited);
			ctl.complete = func;
			ctl.priv = priv;

			int err = dnet_request_cmd(sess.get_native(), &ctl);
			if (err < 0) {
				*error = create_error(err, "failed to request cmd: %s", dnet_cmd_string(ctl.cmd));
				return true;
			}

			return cb.set_count(err);
		}

		bool handle(error_info *error, struct dnet_net_state *state, struct dnet_cmd *cmd, complete_func func, void *priv)
		{
			(void) error;
			return cb.handle(state, cmd, func, priv);
		}

		void finish(const error_info &exc)
		{
			cb.complete(exc);
		}

		session sess;
		dnet_trans_control ctl;
		default_callback<callback_result_entry> cb;
};

class write_callback
{
	public:
		typedef std::shared_ptr<write_callback> ptr;

		write_callback(const session &sess, const async_write_result &result, const dnet_io_control &ctl):
		sess(sess), cb(result), ctl(ctl)
		{
		}

		bool start(error_info *error, complete_func func, void *priv)
		{
			ctl.complete = func;
			ctl.priv = priv;
			cb.set_count(unlimited);

			int err = dnet_write_object(sess.get_native(), &ctl);
			if (err < 0) {
				*error = create_error(err, "Failed to write data");
				return true;
			}
			return cb.set_count(err);
		}

		bool handle(error_info *error, struct dnet_net_state *state, struct dnet_cmd *cmd, complete_func func, void *priv)
		{
			(void) error;
			return cb.handle(state, cmd, func, priv);
		}

		void finish(const error_info &exc)
		{
			cb.complete(exc);
		}

		session sess;
		default_callback<write_result_entry> cb;
		dnet_io_control ctl;
};

class remove_callback
{
	public:
		typedef std::shared_ptr<remove_callback> ptr;

		remove_callback(const session &sess, const async_generic_result &result, const dnet_id &id)
			: sess(sess), cb(result), id(id)
		{
		}

		bool start(error_info *error, complete_func func, void *priv)
		{
			cb.set_count(unlimited);

			const auto &sess_groups = sess.get_groups();
			cb.set_total(sess_groups.size());

			uint64_t cflags_pop = sess.get_cflags();
			sess.set_cflags(cflags_pop | DNET_ATTR_DELETE_HISTORY);
			int err = dnet_remove_object(sess.get_native(), &id,
				func, priv);
			sess.set_cflags(cflags_pop);

			if (err < 0) {
				*error = create_error(err, id, "REMOVE");
				return true;
			} else {
				return cb.set_count(err);
			}
		}

		bool handle(error_info *error, struct dnet_net_state *state, struct dnet_cmd *cmd, complete_func func, void *priv)
		{
			(void) error;
			return cb.handle(state, cmd, func, priv);
		}

		void finish(const error_info &error)
		{
			cb.complete(error);
		}

		session sess;
		default_callback<callback_result_entry> cb;
		dnet_id id;
};

class exec_callback
{
	public:
		typedef std::shared_ptr<exec_callback> ptr;

		exec_callback(const session &sess, const async_exec_result &result)
			: sess(sess), id(NULL), sph(NULL), cb(result)
		{
		}

		bool start(error_info *error, complete_func func, void *priv)
		{
			cb.set_count(unlimited);

			int err = dnet_send_cmd(sess.get_native(), id, func, priv, sph);
			if (err < 0) {
				char buffer[128];
				strncpy(buffer, sph->data, sizeof(buffer));
				buffer[sizeof(buffer) - 1] = '\0';
				*error = create_error(err, "failed to execute cmd: %s", buffer);
				return true;
			}

			return cb.set_count(err);
		}

		bool handle(error_info *error, struct dnet_net_state *state, struct dnet_cmd *cmd, complete_func func, void *priv)
		{
			(void) error;
			return cb.handle(state, cmd, func, priv);
		}

		void finish(const error_info &exc)
		{
			cb.complete(exc);
		}

		session sess;
		struct dnet_id *id;
		struct sph *sph;
		default_callback<exec_result_entry> cb;
};

class iterator_callback
{
	public:
		typedef std::shared_ptr<iterator_callback> ptr;

		iterator_callback(const session &sess, const async_iterator_result &result) : sess(sess), cb(result)
		{
		}

		bool start(error_info *error, complete_func func, void *priv)
		{
			cb.set_count(unlimited);

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
				*error = create_error(err, "failed to start iterator");
				return true;
			}

			return cb.set_count(1);
		}

		bool handle(error_info *error, struct dnet_net_state *state, struct dnet_cmd *cmd, complete_func func, void *priv)
		{
			(void) error;
			return cb.handle(state, cmd, func, priv);
		}

		void finish(const error_info &exc)
		{
			cb.complete(exc);
		}

		session sess;
		struct dnet_id id; /* This ID is used to find out node which will handle iterator request */
		dnet_iterator_request request;
		default_callback<iterator_result_entry> cb;
};

template <typename T>
struct dnet_style_handler
{
	static int handler(struct dnet_net_state *state, struct dnet_cmd *cmd, void *priv)
	{
		T *callback = reinterpret_cast<T*>(priv);
		error_info error;

		if (callback->handle(&error, state, cmd, handler, priv)) {
			finish(callback, error);
		}
		return 0;
	}

	static void start(std::unique_ptr<T> &callback)
	{
		error_info error;
		if (callback->start(&error, handler, callback.get())) {
			if (callback->sess.get_exceptions_policy() & session::throw_at_start)
				error.throw_error();
			// Finish is exception-safe, so it's ok to release
			// the pointer and let finish method to kill it itself
			finish(callback.release(), error);
		} else {
			// Pointer is carried by entire elliptics (it got it through cb->start call)
			// It will be killed as finished is called, which is guaranteed to be called once
			callback.release();
		}
	}

	static void finish(T *callback, const error_info &error)
	{
		callback->finish(error);
		delete callback;
	}
};

template <typename T, typename... Args>
static inline std::unique_ptr<T> createCallback(Args && ...args)
{
	return std::unique_ptr<T>(new T(args...));
}

template <typename T>
static inline void startCallback(std::unique_ptr<T> &cb)
{
	dnet_style_handler<T>::start(cb);
}

} } // namespace ioremap::elliptics

#endif // CALLBACK_P_H
