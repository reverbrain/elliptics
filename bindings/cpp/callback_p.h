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

#include <boost/make_shared.hpp>
#include <boost/thread.hpp>

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

		~callback_result_data()
		{
		}

		data_pointer data;
};

class default_callback
{
	public:
		default_callback() : m_count(1), m_complete(0)
		{
		}

		virtual ~default_callback()
		{
		}

		void set_count(size_t count)
		{
			boost::mutex::scoped_lock lock(m_mutex);
			m_count = count;
		}

		bool handle(struct dnet_net_state *state, struct dnet_cmd *cmd, complete_func, void *)
		{
			boost::mutex::scoped_lock lock(m_mutex);

			if (is_trans_destroyed(state, cmd)) {
				++m_complete;
			} else {
				if (!(cmd->flags & DNET_FLAGS_MORE))
					m_statuses.push_back(cmd->status);
				m_results.push_back(boost::make_shared<callback_result_data>(state, cmd));
			}
			return (m_count == m_complete);
		}

		bool is_ready()
		{
			boost::mutex::scoped_lock lock(m_mutex);
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

		const std::vector<callback_result_entry> &results() const
		{
			return m_results;
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
		boost::mutex m_mutex;
};

template <typename Result, dnet_commands Command>
class base_stat_callback : public default_callback
{
	public:
		base_stat_callback(const session &sess) : sess(sess)
		{
		}

		void start(complete_func func, void *priv)
		{
			int err = dnet_request_stat(sess.get_native(),
				NULL, Command, 0, func, priv);
			if (err < 0) {
				throw_error(err, "Failed to request statistics");
			}
		}

		void finish(std::exception_ptr exc)
		{
			if (exc) {
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
		boost::function<void (const array_result_holder<Result> &)> handler;
};

class stat_callback : public base_stat_callback<stat_result_entry, DNET_CMD_STAT>
{
	public:
		typedef boost::shared_ptr<stat_callback> ptr;

		stat_callback(const session &sess) : base_stat_callback(sess)
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
		typedef boost::shared_ptr<stat_count_callback> ptr;

		stat_count_callback(const session &sess) : base_stat_callback(sess)
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
		multigroup_callback(const session &sess) : sess(sess), at_iterator(false), index(0)
		{
		}

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

		bool iterate_groups(complete_func func, void *priv)
		{
			if (at_iterator)
				return false;
			at_iterator = true;
			// try next group
			while (index < groups.size()) {
				try {
					struct dnet_id id = kid.id();
					id.group_id = groups[index];
					++index;
					next_group(id, func, priv);
					at_iterator = false;
					// request is sent, wait results
					return check_answer();
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
			at_iterator = false;
			// there is no success :(
			notify_about_error();
			throw_error(-ENOENT, kid, "Something happened wrong");
			return false;
		}

		void start(complete_func func, void *priv)
		{
			iterate_groups(func, priv);
		}

		virtual bool check_answer()
		{
			return cb.is_valid();
		}
		virtual void next_group(dnet_id &id, complete_func func, void *priv) = 0;
		virtual void finish(std::exception_ptr exc) = 0;
		virtual void notify_about_error() = 0;

		session sess;
		default_callback cb;
		key kid;
		std::vector<int> groups;

	protected:
		bool at_iterator;
		size_t index;
};

class lookup_callback : public multigroup_callback
{
	public:
		typedef boost::shared_ptr<lookup_callback> ptr;

		lookup_callback(const session &sess) : multigroup_callback(sess)
		{
		}

		void next_group(dnet_id &id, complete_func func, void *priv)
		{
			cb.clear();
			int err = dnet_lookup_object(sess.get_native(), &id, 0, func, priv);
			if (err) {
				throw_error(err, kid, "Failed to lookup ID");
			}
		}

		void finish(std::exception_ptr exc)
		{
			if (exc) {
				handler(exc);
			} else {
				lookup_result_entry result = cb.any_result<lookup_result_entry>();
				dnet_convert_addr_attr(result.address_attribute());
				dnet_convert_file_info(result.file_info());
				handler(result);
			}
		}

		void notify_about_error()
		{
			throw_error(-ENOENT, kid, "Failed to lookup ID");
		}

		boost::function<void (const lookup_result &)> handler;
};

class read_callback : public multigroup_callback
{
	public:
		typedef boost::shared_ptr<read_callback> ptr;

		read_callback(const session &sess, const dnet_io_control &ctl)
			: multigroup_callback(sess), ctl(ctl)
		{
		}

		void next_group(dnet_id &id, complete_func func, void *priv)
		{
			cb.clear();
			memcpy(&ctl.id, &id, sizeof(id));
			ctl.complete = func;
			ctl.priv = priv;
			int err = dnet_read_object(sess.get_native(), &ctl);
			if (err) {
				throw_error(err, ctl.id, "READ: size: %llu",
					static_cast<unsigned long long>(ctl.io.size));
			}
		}

		void finish(std::exception_ptr exc)
		{
			if (exc) {
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
				handler(results);
			}
		}

		void notify_about_error()
		{
			throw_error(-ENOENT, ctl.id, "READ: size: %llu",
				static_cast<unsigned long long>(ctl.io.size));
		}

		struct dnet_io_control ctl;
		boost::function<void (const read_results &)> handler;
};

struct io_attr_comparator
{
	bool operator() (const dnet_io_attr &io1, const dnet_io_attr &io2)
	{
		return memcmp(io1.id, io2.id, DNET_ID_SIZE) < 0;
	}
};

typedef std::set<dnet_io_attr, io_attr_comparator> io_attr_set;

class read_bulk_callback : public read_callback
{
	public:
		typedef boost::shared_ptr<read_bulk_callback> ptr;

		read_bulk_callback(const session &sess, const io_attr_set &ios, const dnet_io_control &ctl)
			: read_callback(sess, ctl), ios_set(ios)
		{
		}

		void next_group(dnet_id &id, complete_func func, void *priv)
		{
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
				int count = 0;

				cb.set_count(0);

				cur = dnet_state_get_first(node, &id);
				if (!cur)
					throw_error(-ENOENT, id, "Can't get state for id");

				for (size_t i = 0; i < io_num; ++i) {
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

					bool last_id = ((i + 1) == io_num);
					++count;

					cb.set_count(count + !last_id);

					int err = dnet_read_object(sess.get_native(), &ctl);
					// ingore the error, we must continue :)
					(void) err;

					cb.set_count(count);

					start = i + 1;
					dnet_state_put(cur);
					cur = next;
					next = NULL;
					memcpy(&id, &next_id, sizeof(struct dnet_id));
				}
			} catch (...) {
				if (cb.is_ready())
					throw;
			}
			if (cb.is_ready())
				throw_error(-ENOENT, id, "bulk_read: can't read data from group %d", id.group_id);
		}

		bool check_answer()
		{
			if (!cb.is_ready())
				return false;
			if (cb.is_valid()) {
				for (size_t i = 0; i < cb.results_size(); ++i) {
					read_result_entry entry = cb.result_at<read_result_entry>(i);
					if (entry.size() < sizeof(struct dnet_io_attr))
						continue;
					result.push_back(entry);
					ios_set.erase(*entry.io_attribute());
				}
			}
			return ios_set.empty() || (index == groups.size());
		}

		void finish(std::exception_ptr exc)
		{
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
		typedef boost::shared_ptr<cmd_callback> ptr;

		cmd_callback(const session &sess, const transport_control &ctl) : sess(sess), ctl(ctl.get_native())
		{
		}

		void start(complete_func func, void *priv)
		{
			ctl.complete = func;
			ctl.priv = priv;

			int err = dnet_request_cmd(sess.get_native(), &ctl);
			if (err < 0) {
				throw_error(err, "failed to request cmd: %s", dnet_cmd_string(ctl.cmd));
			}
			set_count(err);
		}

		void finish(std::exception_ptr exc)
		{
			if (exc)
				handler(exc);
			else
				handler(results());
		}

		session sess;
		dnet_trans_control ctl;
		boost::function<void (const command_result &)> handler;
};

class prepare_latest_callback : public default_callback
{
	public:
		typedef boost::shared_ptr<prepare_latest_callback> ptr;

		class entry
		{
			public:
				struct dnet_id *id;
				struct dnet_file_info *fi;

				bool operator <(const entry &other) const
				{
					return (fi->mtime.tsec < other.fi->mtime.tsec)
						|| (fi->mtime.tsec == other.fi->mtime.tsec
							&& (fi->mtime.tnsec < other.fi->mtime.tnsec));
				}

				bool operator ==(const entry &other) const
				{
					return fi->mtime.tsec == other.fi->mtime.tsec
						&& fi->mtime.tnsec == other.fi->mtime.tnsec;
				}
		};

		prepare_latest_callback(const session &sess, const std::vector<int> &groups) : sess(sess), groups(groups)
		{
			cflags = DNET_ATTR_META_TIMES | sess.get_cflags();
		}

		void start(complete_func func, void *priv)
		{
			set_count(groups.size());
			dnet_id raw = id.id();
			for (size_t i = 0; i < groups.size(); ++i) {
				raw.group_id = groups[i];
				dnet_lookup_object(sess.get_native(), &raw, cflags, func, priv);
			}
		}

		void finish(std::exception_ptr exc)
		{
			if (exc) {
				handler(exc);
			}

			std::vector<entry> entries(results().size());
			for (size_t i = 0; i < entries.size(); ++i) {
				entry &e = entries[i];
				const lookup_result_entry &le = result_at<lookup_result_entry>(i);
				e.fi = le.file_info();
				e.id = &le.command()->id;
			}

			std::sort(entries.begin(), entries.end());

			for (size_t i = 1; i < entries.size(); ++i) {
				if (entries[i].id->group_id == group_id
					&& entries[i] == entries[0]) {
					std::swap(entries[i], entries[0]);
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
		uint64_t cflags;
		boost::function<void (const prepare_latest_result &)> handler;
};

template <typename T>
void check_for_exception(const result_holder<T> &result)
{
	result.check();
}

template <typename T>
void check_for_exception(const array_result_holder<T> &result)
{
	result.check();
}

template <typename T>
class waiter
{
	ELLIPTICS_DISABLE_COPY(waiter)
	public:
		class handler_impl
		{
			public:
				explicit handler_impl(waiter *parent) : m_parent(parent) {}

				void operator() (const T &result)
				{
					std::cerr << "result!" << std::endl;
					m_parent->handle_result(result);
				}

			private:
				waiter *m_parent;

		};

		waiter() : m_result_ready(false)
		{
		}

		const T &result()
		{
			wait();
			check_for_exception(m_result);
			return m_result;
		}

		handler_impl handler()
		{
			return handler_impl(this);
		}

		void handle_result(const T &result)
		{
			{
				boost::mutex::scoped_lock locker(m_mutex);
				m_result = result;
				m_result_ready = true;
			}
			m_condition.notify_all();
		}

		void wait()
		{
			boost::mutex::scoped_lock locker(m_mutex);

			while (!m_result_ready)
				m_condition.wait(locker);
		}

	private:
		boost::mutex			m_mutex;
		boost::condition_variable	m_condition;
		T				m_result;
		bool				m_result_ready;
};

template <typename T>
struct dnet_style_handler
{
	static int handler(struct dnet_net_state *state, struct dnet_cmd *cmd, void *priv)
	{
		boost::shared_ptr<T> &ptr = *reinterpret_cast<boost::shared_ptr<T> *>(priv);

		bool finish = false;
		std::exception_ptr exc_ptr;
		try {
			finish = ptr->handle(state, cmd, handler, priv);
		} catch (...) {
			exc_ptr = std::current_exception();
			finish = true;
		}

		if (finish) {
			try {
				ptr->finish(exc_ptr);
			} catch (...) {
			}

			delete &ptr;
		}
		return 0;
	}

	static void start(const boost::shared_ptr<T> &cb)
	{
		boost::shared_ptr<T> *cb_ptr = new boost::shared_ptr<T>(cb);
		cb->start(handler, cb_ptr);
	}
};

} } // namespace ioremap::elliptics

#endif // CALLBACK_P_H
