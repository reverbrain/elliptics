/*
 * 2008+ Copyright (c) Evgeniy Polyakov <zbr@ioremap.net>
 * 2012+ Copyright (c) Ruslan Nigmatullin <euroelessar@yandex.ru>
 * All rights reserved.
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU Lesser General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU Lesser General Public License for more details.
 */

#ifndef CALLBACK_P_H
#define CALLBACK_P_H

#include "elliptics/cppdef.h"

#include <algorithm>
#include <cassert>
#include <condition_variable>
#include <exception>
#include <iostream>
#include <mutex>
#include <set>
#include <sstream>
#include <thread>

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
			data = data_pointer::allocate(size);
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
		typedef std::function<void (const T &)> entry_processor_func;

		default_callback(const session &sess, const async_result<T> &result)
			: m_logger(sess.get_logger()),
			  m_count(1), m_complete(0), m_result(result), m_proto_error(false)
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
				if (!(cmd->flags & DNET_FLAGS_MORE)) {
					if (m_proto_error && cmd->status == 0) {
						m_statuses.push_back(-EPROTO);
						m_proto_error = 0;
					} else {
						m_statuses.push_back(cmd->status);
					}
				}
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
			if (!entry.data().empty()) {
				try {
					entry_converter::convert(entry, data);
				} catch (...) {
					m_logger.print(DNET_LOG_ERROR, "%s: received invalid data from server, tid: %llu, cmd: %s, status: %d, size: %llu\n",
						       dnet_dump_id(&cmd->id),
						       static_cast<unsigned long long>(cmd->trans),
						       dnet_cmd_string(cmd->cmd),
						       cmd->status,
						       static_cast<unsigned long long>(cmd->size));

					dnet_cmd *cmd_copy = default_entry.command();
					if (cmd_copy->status == 0)
						cmd_copy->status = -EPROTO;
					if (cmd_copy->flags & DNET_FLAGS_MORE) {
						m_proto_error = true;
					} else {
						m_statuses.back() = cmd_copy->status;
					}

					cmd_copy->flags &= ~DNET_FLAGS_MORE;
					cmd_copy->size = 0;

					data->data = data->data.slice(0, sizeof(dnet_addr) + sizeof(dnet_cmd));
				}
			}
			process(entry);
		}

		void process(const T &entry)
		{
			if (m_process_entry && entry.status() == 0 && !entry.data().empty()) {
				m_process_entry(entry);
			}

			m_result.process(entry);
		}

		void set_process_entry(const entry_processor_func &process_entry)
		{
			m_process_entry = process_entry;
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
			m_proto_error = false;
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
		logger m_logger;
		size_t m_count;
		size_t m_complete;
		std::vector<int> m_statuses;
		std::mutex m_mutex;
		entry_processor_func m_process_entry;
		typename async_result<T>::handler m_result;
		bool m_proto_error;
};

template <typename Result, dnet_commands Command>
class base_stat_callback
{
	public:
		base_stat_callback(const session &sess, const async_result<Result> &result)
			: sess(sess), cb(sess, result), has_id(false)
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
			: sess(sess), cb(sess, result), m_has_finished(false), m_group_index(0)
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
			dnet_log_raw(sess.get_native_node(),
				DNET_LOG_DEBUG, "%s: multigroup_callback::handle: cmd: %s, trans: %llx, status: %d, flags: %llx, group: %d: %zd/%zd, priv: %p\n",
					dnet_dump_id(&cmd->id), dnet_cmd_string(cmd->cmd), static_cast<long long unsigned>(cmd->trans),
					cmd->status, static_cast<long long unsigned>(cmd->flags),
					groups[m_group_index], m_group_index, groups.size(), priv);

			if (cb.handle(state, cmd, func, priv)) {
				m_has_finished |= !cb.statuses().empty();
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

			dnet_log_raw(sess.get_native_node(),
				DNET_LOG_DEBUG, "multigroup_callback::iterate_groups: group: %d: %zd/%zd, error: %d, priv: %p\n",
					groups[m_group_index], m_group_index, groups.size(), error->code(), priv);
			// try next group
			while (m_group_index < groups.size()) {
				struct dnet_id id = kid.id();
				id.group_id = groups[m_group_index];

				++m_group_index;

				if (next_group(error, id, func, priv)) {
					if (error->code()) {
						// some exception, log and try next group
						dnet_log_raw(sess.get_native_node(),
							DNET_LOG_NOTICE,
							"%s: iterate-groups exception: %s\n",
							dnet_dump_id(&id), error->message().c_str());
						*error = error_info();
						continue;
					}
					m_has_finished |= !cb.statuses().empty();
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
			if (!m_has_finished) {
				*error = prepare_error();
			}
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
		bool m_has_finished;
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

			dnet_log_raw(sess.get_native_node(), DNET_LOG_DEBUG, "lookup_callback::next_group: %s: error: %d, priv: %p\n",
					dnet_dump_id(&id), error->code(), priv);

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
			return create_error(-ENXIO, kid, "Failed to lookup ID");
		}
};

class read_callback : public multigroup_callback<read_result_entry>
{
	public:
		typedef std::shared_ptr<read_callback> ptr;

		read_callback(const session &sess, const async_read_result &result, const dnet_io_control &ctl)
			: multigroup_callback<read_result_entry>(sess, result), ctl(ctl)
		{
			cb.set_process_entry(std::bind(&read_callback::process_entry, this, std::placeholders::_1));
		}

		bool next_group(error_info *error, dnet_id &id, complete_func func, void *priv)
		{
			cb.clear();
			cb.set_count(unlimited);

			memcpy(&ctl.id, &id, sizeof(id));
			ctl.complete = func;
			ctl.priv = priv;

			int err = dnet_read_object(sess.get_native(), &ctl);

			dnet_log_raw(sess.get_native_node(), DNET_LOG_DEBUG, "read_callback::next_group: %s: error: %d, priv: %p, err: %d\n",
					dnet_dump_id(&id), error->code(), priv, err);

			if (err) {
				*error = create_error(err, ctl.id, "READ: size: %llu",
					static_cast<unsigned long long>(ctl.io.size));
				return true;
			}

			return cb.set_count(1);
		}

		void process_entry(const read_result_entry &entry)
		{
			read_result = entry;
		}

		void finish(const error_info &error)
		{
			dnet_io_attr *io = (read_result.is_valid() ? read_result.io_attribute() : NULL);

			if (!error && !failed_groups.empty()
					&& io
					&& (io->size == io->total_size)
					&& (io->offset == 0)) {

				session new_sess = sess.clone();
				new_sess.set_groups(failed_groups);

				dnet_io_control write_ctl;
				memcpy(&write_ctl, &ctl, sizeof(write_ctl));

				write_ctl.id = kid.id();
				write_ctl.io = *io;

				write_ctl.data = read_result.file().data();
				write_ctl.io.size = read_result.file().size();

				write_ctl.fd = -1;
				write_ctl.cmd = DNET_CMD_WRITE;
				write_ctl.cflags = ctl.cflags;


				std::ostringstream ss;
				for (auto g = failed_groups.begin(); g != failed_groups.end();) {
					ss << *g;

					if (++g != failed_groups.end())
						ss << ":";
				}

				dnet_log_raw(sess.get_node().get_native(), DNET_LOG_INFO,
						"read_callback::read-recovery: %s: %llu bytes -> %s groups\n",
					dnet_dump_id_str(io->id), (unsigned long long)io->size, ss.str().c_str());

				new_sess.write_data(write_ctl);
			}

			cb.complete(error);
		}

		virtual bool check_answer()
		{
			const auto &statuses = cb.statuses();

			if (statuses.empty()) {
				return false;
			}

			bool has_enoent = false;
			bool has_other_error = false;
			bool ok = false;

			for (size_t i = 0; i < statuses.size(); ++i) {
				const int err = statuses[i];

				if (err == -ENOENT || err == -EBADFD) {
					has_enoent = true;
				} else if (err != 0) {
					has_other_error = true;
				} else if (err == 0) {
					ok = true;
				}
			}

			if (!ok && has_enoent && !has_other_error) {
				failed_groups.push_back(groups[m_group_index - 1]);
			}

			return ok;
		}

		error_info prepare_error()
		{
			return create_error(-ENXIO, ctl.id, "READ: size: %llu",
				static_cast<unsigned long long>(ctl.io.size));
		}

		struct dnet_io_control ctl;
		std::vector<int> failed_groups;
		read_result_entry read_result;
};

struct io_attr_comparator
{
	bool operator() (const dnet_io_attr &io1, const dnet_io_attr &io2)
	{
		return memcmp(io1.id, io2.id, DNET_ID_SIZE) < 0;
	}
};

typedef std::set<dnet_io_attr, io_attr_comparator> io_attr_set;

struct dnet_net_state_deleter
{
	void operator () (dnet_net_state *state) const
	{
		if (state)
			dnet_state_put(state);
	}
};

typedef std::unique_ptr<dnet_net_state, dnet_net_state_deleter> net_state_ptr;

#define elliptics_log(LEVEL, a...) do { if (log.get_log_level() >= LEVEL) log.print(LEVEL, ##a); } while (0)
#define debug(a...) elliptics_log(DNET_LOG_DEBUG, ##a)
#define notice(a...) elliptics_log(DNET_LOG_NOTICE, ##a)

class read_bulk_callback : public read_callback
{
	public:
		typedef std::shared_ptr<read_bulk_callback> ptr;

		read_bulk_callback(const session &sess, const async_read_result &result, const io_attr_set &ios, const dnet_io_control &ctl)
			: read_callback(sess, result, ctl), log(sess.get_logger()), ios_set(ios)
		{
			cb.set_process_entry(default_callback<read_result_entry>::entry_processor_func());
			debug("BULK_READ, callback: %p, ios.size: %zu", this, ios.size());
		}

		bool handle(error_info *error, struct dnet_net_state *state, struct dnet_cmd *cmd, complete_func func, void *priv)
		{
			debug("BULK_READ, callback: %p, id: %s, err: %d, size: %llu",
				this, dnet_dump_id(&cmd->id), cmd->status, (unsigned long long)cmd->size);
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

			int count = 0;

			ios_cache.assign(ios_set.begin(), ios_set.end());
			const size_t io_num = ios_cache.size();
			dnet_io_attr *ios = ios_cache.data();

			dnet_node *node = sess.get_native_node();
			net_state_ptr cur, next;
			dnet_id next_id = id;
			const int group_id = id.group_id;
			int start = 0;

			dnet_setup_id(&id, group_id, ios[0].id);

			debug("BULK_READ, callback: %p, group: %d, next", this, group_id);

			cur.reset(dnet_state_get_first(node, &id));
			if (!cur) {
				debug("BULK_READ, callback: %p, group: %d, id: %s, state: failed",
					this, group_id, dnet_dump_id(&id));
				*error = create_error(-ENOENT, id, "Can't get state for id");
				return true;
			}
			debug("BULK_READ, callback: %p, id: %s, state: %s",
				this, dnet_dump_id(&id), dnet_state_dump_addr(cur.get()));

			for (size_t i = 0; i < io_num; ++i) {
				if ((i + 1) < io_num) {
					dnet_setup_id(&next_id, group_id, ios[i + 1].id);

					next.reset(dnet_state_get_first(node, &next_id));
					if (!next) {
						debug("BULK_READ, callback: %p, group: %d, id: %s, state: failed",
							this, group_id, dnet_dump_id(&next_id));
						*error = create_error(-ENOENT, next_id, "Can't get state for id");
						if (cb.set_count(count))
							return true;
						return false;
					}
					debug("BULK_READ, callback: %p, id: %s, state: %s",
						this, dnet_dump_id(&next_id), dnet_state_dump_addr(next.get()));

					/* Send command only if state changes or it's a last id */
					if (cur == next) {
						next.reset();
						continue;
					}
				}

				ctl.io.size = (i - start + 1) * sizeof(struct dnet_io_attr);
				ctl.data = ios + start;

				memcpy(&ctl.id, &id, sizeof(id));
				ctl.complete = func;
				ctl.priv = priv;

				notice("BULK_READ, callback: %p, start: %s: end: %s, count: %llu, addr: %s\n",
					this,
					dnet_dump_id(&id),
					dnet_dump_id(&next_id),
					(unsigned long long)ctl.io.size / sizeof(struct dnet_io_attr),
					dnet_state_dump_addr(cur.get()));

				++count;

				int err = dnet_read_object(sess.get_native(), &ctl);
				// ingore the error, we must continue :)
				debug("BULK_READ, callback: %p, group: %d, err: %d", this, group_id, err);

				start = i + 1;
				cur.reset();
				std::swap(cur, next);
				memcpy(&id, &next_id, sizeof(struct dnet_id));
			}

			debug("BULK_READ, callback: %p, group: %d, count: %d", this, group_id, count);
			return cb.set_count(count);
		}

		bool check_answer()
		{
			elliptics_assert(cb.is_ready());
			debug("BULK_READ, callback: %p, ios_set.size: %zu, group_index: %zu, group_count: %zu",
			      this, ios_set.size(), m_group_index, groups.size());

			// all results are found or all groups are iterated
			return ios_set.empty() || (m_group_index == groups.size());
		}

		void finish(const error_info &exc)
		{
			debug("BULK_READ, callback: %p, err: %s", this, exc.message().c_str());
			cb.complete(exc);
		}

		error_info prepare_error()
		{
			return create_error(-ENXIO, "bulk_read: can't read data");
		}

		logger log;
		std::mutex ios_set_mutex;
		io_attr_set ios_set;
		std::vector<dnet_io_attr> ios_cache;
		std::vector<read_result_entry> result;
};

class find_indexes_callback : public multigroup_callback<callback_result_entry>
{
	public:
		typedef std::map<dnet_raw_id, dnet_raw_id, dnet_raw_id_less_than<> > id_map;
		typedef std::shared_ptr<find_indexes_callback> ptr;

		struct index_id
		{
			index_id(const dnet_raw_id &id, int shard_id) :
				id(id), shard_id(shard_id)
			{
			}

			bool operator <(const index_id &other) const
			{
				return dnet_id_cmp_str(id.id, other.id.id) < 0;
			}

			dnet_raw_id id;
			int shard_id;
		};

		find_indexes_callback(const session &arg_sess, const std::vector<dnet_raw_id> &indexes,
			bool intersect, const async_generic_result &result) :
			multigroup_callback<callback_result_entry>(arg_sess, result),
			log(sess.get_logger()),
			intersect(intersect),
			shard_count(dnet_node_get_indexes_shard_count(sess.get_native_node())),
			indexes(indexes)
		{
			dnet_node *node = sess.get_native_node();

			id_precalc.resize(shard_count * indexes.size());

			/*
			 * index_requests_set contains all requests we have to send for this bulk-request.
			 * All indexes a splitted for shards, so we have to send separate logical request
			 * to certain shard for all indexes. This logical requests may be joined to one
			 * transaction if some of shards are situated on one elliptics node.
			 */
			dnet_raw_id tmp;

			for (size_t index = 0; index < indexes.size(); ++index) {
				dnet_indexes_transform_index_prepare(node, &indexes[index], &tmp);

				for (int shard_id = 0; shard_id < shard_count; ++shard_id) {
					dnet_raw_id &id = id_precalc[shard_id * indexes.size() + index];

					memcpy(&id, &tmp, sizeof(dnet_raw_id));
					dnet_indexes_transform_index_id_raw(node, &id, shard_id);

					convert_map[id] = indexes[index];
				}
			}

			for (int shard_id = 0; shard_id < shard_count; ++shard_id) {
				index_requests_set.insert(index_id(id_precalc[shard_id * indexes.size()], shard_id));
			}

			debug("INDEXES_FIND, callback: %p, shard_count: %d, indexes_count: %zu", this, shard_count, indexes.size());
		}

		/*
		 * This method is called on every reply packet received from the server nodes.
		 * If reply for some shard is positive - remove it from the index_requests_set,
		 * so this request won't be send to the next group.
		 * If cmd->size is zero it is just acknowledge and it's not a reply for any certain
		 * shard.
		 *
		 * This method returnes true if all requests are processed and we have nothing to do more.
		 */
		bool handle(error_info *error, struct dnet_net_state *state, struct dnet_cmd *cmd, complete_func func, void *priv)
		{
			debug("INDEXES_FIND, callback: %p, id: %s, err: %d, size: %llu",
				this, dnet_dump_id(&cmd->id), cmd->status, (unsigned long long)cmd->size);
			// Remove from ios_set entries for which result is ready
			if (cmd->status == 0 && cmd->size > 0) {
				std::lock_guard<std::mutex> lock(index_requests_mutex);
				auto &id = reinterpret_cast<dnet_raw_id&>(cmd->id);
				index_requests_set.erase(index_id(id, 0));
			}
			return multigroup_callback<callback_result_entry>::handle(error, state, cmd, func, priv);
		}

		/*
		 * This method is called for every group by the order until all of them a processed
		 * or received replies for every request.
		 *
		 * Method is called for the next group only after last reply for previous one is
		 * received. This logic is implemented in multigroup_callback.
		 */
		bool next_group(error_info *error, dnet_id &id, complete_func func, void *priv)
		{
			cb.clear();
			cb.set_count(unlimited);

			int count = 0;
			unsigned long long index_requests_count = 0;
			const int group_id = id.group_id;

			dnet_node *node = sess.get_native_node();
			dnet_setup_id(&id, group_id, index_requests_set.begin()->id.id);
			net_state_ptr cur(dnet_state_get_first(node, &id));
			net_state_ptr next;
			dnet_id next_id = id;

			debug("INDEXES_FIND, callback: %p, group: %d, next", this, group_id);

			if (!cur) {
				debug("INDEXES_FIND, callback: %p, group: %d, id: %s, state: failed",
					this, group_id, dnet_dump_id(&id));
				*error = create_error(-ENOENT, id, "Can't get state for id");
				return true;
			}
			debug("INDEXES_FIND, callback: %p, id: %s, state: %s",
				this, dnet_dump_id(&id), dnet_state_dump_addr(cur.get()));

			dnet_trans_control control;
			memset(&control, 0, sizeof(control));
			control.cmd = DNET_CMD_INDEXES_FIND;
			control.cflags = DNET_FLAGS_NEED_ACK;

			data_buffer buffer;

			dnet_indexes_request request;
			memset(&request, 0, sizeof(request));
			request.entries_count = indexes.size();
			request.id = id;
			if (intersect)
				request.flags |= DNET_INDEXES_FLAGS_INTERSECT;
			else
				request.flags |= DNET_INDEXES_FLAGS_UNITE;

			dnet_indexes_request_entry entry;
			memset(&entry, 0, sizeof(entry));

			std::vector<index_id> index_requests(index_requests_set.begin(), index_requests_set.end());

			/*
			 * We have to keep API/ABI compatibility for all 2.24 life but bulk find indexes requests
			 * is a new functionality which replaces already existen one. So we have to simulate old-style
			 * separate requests to hosts which don't know anything about bulk find yet.
			 */
			int version[] = { 2, 24, 14, 22 };

			/*
			 * Iterate through all requests uniting to single transaction all for the same host.
			 */
			for (auto it = index_requests.begin(); it != index_requests.end(); ++it) {
				bool more = false;
				/*
				 * Check for the state of the next request if current is not the last one.
				 * If next state is the same we should unite requests to single one.
				 */
				auto jt = it;
				if (++jt != index_requests.end()) {
					dnet_setup_id(&next_id, group_id, jt->id.id);

					next.reset(dnet_state_get_first(node, &next_id));
					if (!next) {
						debug("INDEXES_FIND, callback: %p, group: %d, id: %s, state: failed",
							this, group_id, dnet_dump_id(&next_id));
						*error = create_error(-ENOENT, next_id, "Can't get state for id");
						if (cb.set_count(count))
							return true;
						return false;
					}
					debug("INDEXES_FIND, callback: %p, id: %s, state: %s",
						this, dnet_dump_id(&next_id), dnet_state_dump_addr(next.get()));

					/* Send command only if state changes or it's a last id */
					int cmp = dnet_version_compare(cur.get(), version);
					more = (cmp >= 0) && (cur == next);
				}

				if (more) {
					request.flags |= DNET_INDEXES_FLAGS_MORE;
				} else {
					request.flags &= ~DNET_INDEXES_FLAGS_MORE;
				}
				dnet_setup_id(&request.id, group_id, id_precalc[it->shard_id * indexes.size()].id);

				buffer.write(request);
				++index_requests_count;

				for (size_t i = 0; i < indexes.size(); ++i) {
					entry.id = id_precalc[it->shard_id * indexes.size() + i];
					buffer.write(entry);
				}

				if (more) {
					continue;
				}

				data_pointer data = std::move(buffer);

				control.size = data.size();
				control.data = data.data();

				memcpy(&control.id, &id, sizeof(id));
				control.complete = func;
				control.priv = priv;

				notice("INDEXES_FIND: callback: %p, count: %llu, state: %s\n",
					this,
					index_requests_count,
					dnet_state_dump_addr(cur.get()));

				++count;
				index_requests_count = 0;

				int err = dnet_trans_alloc_send(sess.get_native(), &control);
				/*
				 * Ingore the error, we must continue :)
				 * If transaction is failed on this stage it still calls handler method
				 * so it's counted as finished one. That is why we have to increment the counter.
				 *
				 * Also the exact error code doesn't really matter as we should give user -ENXIO
				 * error in such case.
				 */
				debug("INDEXES_FIND, callback: %p, group: %d, err: %d", this, group_id, err);

				cur.reset();
				std::swap(next, cur);
				memcpy(&id, &next_id, sizeof(struct dnet_id));
			}

			debug("INDEXES_FIND, callback: %p, group: %d, count: %d", this, group_id, count);
			return cb.set_count(count);
		}

		bool check_answer()
		{
			elliptics_assert(cb.is_ready());
			debug("INDEXES_FIND, callback: %p, index_requests_set.size: %zu, group_index: %zu, group_count: %zu",
			      this, index_requests_set.size(), m_group_index, groups.size());
			// all results are found or all groups are iterated
			return index_requests_set.empty() || (m_group_index == groups.size());
		}

		void finish(const error_info &exc)
		{
			debug("INDEXES_FIND, callback: %p, err: %s", this, exc.message().c_str());
			cb.complete(exc);
		}

		error_info prepare_error()
		{
			return create_error(-ENXIO, "indexes_find: can't read data");
		}

		logger log;
		const bool intersect;
		const int shard_count;
		std::mutex index_requests_mutex;
		std::set<index_id> index_requests_set;
		id_map convert_map;
		std::vector<dnet_raw_id> id_precalc;
		std::vector<dnet_raw_id> indexes;
};

class cmd_callback
{
	public:
		typedef std::shared_ptr<cmd_callback> ptr;

		cmd_callback(const session &sess, const async_generic_result &result, const transport_control &ctl)
			: sess(sess), ctl(ctl.get_native()), cb(sess, result)
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

class single_cmd_callback
{
	public:
		typedef std::shared_ptr<single_cmd_callback> ptr;

		single_cmd_callback(const session &sess, const async_generic_result &result, const transport_control &ctl)
			: sess(sess), ctl(ctl.get_native()), cb(sess, result)
		{
		}

		bool start(error_info *error, complete_func func, void *priv)
		{
			cb.set_count(unlimited);
			ctl.complete = func;
			ctl.priv = priv;

			int err = dnet_trans_alloc_send(sess.get_native(), &ctl);
			if (err < 0) {
				*error = create_error(err, "failed to request cmd: %s", dnet_cmd_string(ctl.cmd));
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
		dnet_trans_control ctl;
		default_callback<callback_result_entry> cb;
};

class remove_index_callback
{
	public:
		typedef std::shared_ptr<remove_index_callback> ptr;

		remove_index_callback(const session &sess, const async_generic_result &result, const dnet_raw_id &index)
			: sess(sess), flags(0), cb(sess, result), index(index)
		{
		}

		struct state_container
		{
			state_container() : entries_count(0), failed(false)
			{
			}

			state_container(const state_container &other) = delete;
			state_container(state_container &&other) = delete;

			state_container &operator =(const state_container &other) = delete;
			state_container &operator =(state_container &&other) = delete;

			net_state_ptr cur;
			data_buffer buffer;
			size_t entries_count;
			bool failed;
		};

		bool start(error_info *error, complete_func func, void *priv)
		{
			(void) error;

			cb.set_count(unlimited);
			size_t count = 0;

			dnet_node *node = sess.get_native_node();
			const int shard_count = dnet_node_get_indexes_shard_count(node);

			dnet_trans_control control;
			memset(&control, 0, sizeof(control));

			control.cmd = DNET_CMD_INDEXES_INTERNAL;
			control.cflags |= DNET_FLAGS_NEED_ACK;
			control.complete = func;
			control.priv = priv;

			dnet_indexes_request request;
			memset(&request, 0, sizeof(request));

			dnet_indexes_request_entry entry;
			memset(&entry, 0, sizeof(entry));

			entry.flags |= DNET_INDEXES_FLAGS_INTERNAL_REMOVE_ALL | flags;

			std::unique_ptr<state_container[]> states(new state_container[groups.size()]);

			std::vector<int> single_group(1, 0);

			dnet_id id;
			memset(&id, 0, DNET_ID_SIZE);

			/*
			 * To totally remove the index we have to send remove request to every shard and to every group.
			 * Sending 4k different requests is not optimatl, so requests to the single elliptics node
			 * are joined to the single request.
			 *
			 * To do this we have to iterate through all shards. It's needed for every (shard, group) pair
			 * to compare dnet_net_state with (shard - 1, group) one if it exists.
			 */

			for (int shard_id = 0; shard_id <= shard_count; ++shard_id) {
				const bool after_last_entry = (shard_id == shard_count);

				if (!after_last_entry) {
					dnet_indexes_transform_index_id(node, &index, &entry.id, shard_id);
					memcpy(id.id, entry.id.id, DNET_ID_SIZE);
				}

				/*
				 * Iterate for all groups, each group stores it's state it states[group_index] field.
				 * It's needed to decrease number of index transformations above.
				 */
				for (size_t group_index = 0; group_index < groups.size(); ++group_index) {
					state_container &state = states[group_index];

					// We failed to get this group's network state sometime ago so skip it
					if (state.failed) {
						continue;
					}

					id.group_id = groups[group_index];
					net_state_ptr next;

					if (shard_id == 0) {
						state.cur.reset(dnet_state_get_first(node, &id));
						// Error during state getting, don't touch this group more
						if (!state.cur) {
							state.failed = true;
							continue;
						}
					}

					if (!after_last_entry) {
						next.reset(dnet_state_get_first(node, &id));
						// Error during state getting, don't touch this group more
						if (!next) {
							state.failed = true;
							continue;
						}
					}

					// This is a first entry, prepend the request to the buffer
					if (state.entries_count == 0) {
						if (after_last_entry) {
							// Oh, this was not the first entry, but we already finished this group
							continue;
						}
						request.id = id;
						state.buffer.write(request);
					}

					if (state.cur == next) {
						// Append entry to the request list as they are to the same node
						state.buffer.write(entry);
						state.entries_count++;
						continue;
					} else {
						state.cur = std::move(next);
					}

					data_pointer data = std::move(state.buffer);

					// Set the actual entries_count value as it is unknown at the beginning
					dnet_indexes_request *request_ptr = data.data<dnet_indexes_request>();
					request_ptr->entries_count = state.entries_count;
					dnet_setup_id(&request_ptr->id, id.group_id, request_ptr->entries[0].id.id);
					state.entries_count = 0;

					control.id = request_ptr->id;
					control.data = data.data();
					control.size = data.size();

					single_group[0] = groups[group_index];
					sess.set_groups(single_group);

					// Send exactly one request to exactly one elliptics node
					int err = dnet_trans_alloc_send(sess.get_native(), &control);
					(void) err;

					++count;

					if (!after_last_entry) {
						state.buffer.write(request);
						state.buffer.write(entry);
						state.entries_count++;
					}
				}
			}

			return cb.set_count(count);
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
		uint64_t flags;
		default_callback<callback_result_entry> cb;
		dnet_raw_id index;
		std::vector<int> groups;
};

class write_callback
{
	public:
		typedef std::shared_ptr<write_callback> ptr;

		write_callback(const session &sess, const async_write_result &result, const dnet_io_control &ctl):
		sess(sess), cb(sess, result), ctl(ctl)
		{
		}

		bool start(error_info *error, complete_func func, void *priv)
		{
			ctl.complete = func;
			ctl.priv = priv;

			cb.set_total(sess.get_groups().size());

			if (dnet_time_is_empty(&ctl.io.timestamp)) {
				sess.get_timestamp(&ctl.io.timestamp);

				if (dnet_time_is_empty(&ctl.io.timestamp))
					dnet_current_time(&ctl.io.timestamp);
			}

			if (ctl.io.user_flags == 0)
				ctl.io.user_flags = sess.get_user_flags();

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
			: sess(sess), cb(sess, result), id(id)
		{
		}

		bool start(error_info *error, complete_func func, void *priv)
		{
			cb.set_count(unlimited);

			const auto &sess_groups = sess.get_groups();
			cb.set_total(sess_groups.size());

			int err = dnet_remove_object(sess.get_native(), &id, func, priv);

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
			: sess(sess), id(NULL), sph(NULL), cb(sess, result)
		{
		}

		bool start(error_info *error, complete_func func, void *priv)
		{
			cb.set_count(unlimited);

			int err = dnet_send_cmd(sess.get_native(), id, func, priv, sph);
			if (err < 0) {
				*error = create_error(err, "failed to execute cmd: event: %.*s, data-size: %llu",
						sph->event_size, sph->data, (unsigned long long)sph->data_size);
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

		iterator_callback(const session &sess, const async_iterator_result &result) : sess(sess), cb(sess, result)
		{
		}

		bool start(error_info *error, complete_func func, void *priv)
		{
			cb.set_count(unlimited);

			dnet_trans_control ctl;
			memset(&ctl, 0, sizeof(ctl));
			memcpy(&ctl.id, &id, sizeof(id));
			ctl.id.group_id = sess.get_groups().front();
			ctl.cflags = sess.get_cflags() | DNET_FLAGS_NEED_ACK | DNET_FLAGS_NOLOCK;
			ctl.cmd = DNET_CMD_ITERATOR;
			ctl.complete = func;
			ctl.priv = priv;

			dnet_convert_iterator_request(request.data<dnet_iterator_request>());
			ctl.data = request.data();
			ctl.size = request.size();

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
		data_pointer request;
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
