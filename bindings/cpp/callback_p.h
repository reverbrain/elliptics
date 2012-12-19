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
			memcpy(data.data(), cmd, sizeof(struct dnet_cmd) + cmd->size);
		}

		~callback_result_data()
		{
		}

		data_pointer data;

	private:
};

class default_callback
{
	public:
		typedef boost::shared_ptr<default_callback> ptr;

		default_callback() : m_count(1), m_complete(0)
		{
		}

		virtual ~default_callback()
		{
		}

		void set_count(size_t count)
		{
			m_count = count;
		}

		bool handle(struct dnet_net_state *state, struct dnet_cmd *cmd, complete_func, void *)
		{
			if (is_trans_destroyed(state, cmd)) {
				++m_complete;
			} else {
				if (!(cmd->flags & DNET_FLAGS_MORE))
					m_statuses.push_back(cmd->status);
				m_results.push_back(boost::make_shared<callback_result_data>(state, cmd));
			}
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
		T result_at(size_t index) const
		{
			return *static_cast<const T *>(&m_results.at(index));
		}

		const std::vector<callback_result_entry> &results() const
		{
			return m_results;
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

		void finish(boost::exception_ptr exc)
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
				} catch (std::exception &e) {
					exc = boost::copy_exception(e);
				}
				handler(exc);
			} else {
				handler(res);
			}
		}

		virtual bool convert(Result &result) = 0;

		dnet_commands command;
		session sess;
		boost::recursive_mutex mutex;
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

class lookup_callback
{
	public:
		typedef boost::shared_ptr<lookup_callback> ptr;

		lookup_callback(const session &sess) : at_iterator(false), sess(sess), index(0)
		{
		}

		bool handle(struct dnet_net_state *state, struct dnet_cmd *cmd, complete_func func, void *priv)
		{
			if (cb.handle(state, cmd, func, priv)) {
				// cb has ended it's work
				if (cb.is_valid()) {
					// correct answer is found
					return true;
				} else {
					iterate_groups(func, priv);
					return false;
				}
			}
			return false;
		}

		void iterate_groups(complete_func func, void *priv)
		{
			if (at_iterator)
				return;
			at_iterator = true;
			// try next group
			while (index < groups.size()) {
				try {
					id.group_id = groups[index];
					++index;
					next_group(id, func, priv);
					at_iterator = false;
					// request is sent, wait results
					return;
				} catch (std::exception &e) {
					// some exception, log and try next group
					if (kid.by_id()) {
						dnet_log_raw(sess.get_node().get_native(),
							DNET_LOG_ERROR,
							"%s: %s\n",
							dnet_dump_id(&id),
							e.what());
					} else {
						dnet_log_raw(sess.get_node().get_native(),
							DNET_LOG_ERROR,
							"%s: %s : %s\n",
							dnet_dump_id(&id),
							e.what(),
							kid.remote().c_str());
					}
				}
			}
			typedef boost::shared_ptr<lookup_callback> ptr;
			at_iterator = false;
			// there is no success :(
			throw_error(-ENOENT, kid, "Failed to lookup ID");
		}

		void start(complete_func func, void *priv)
		{
			boost::recursive_mutex::scoped_lock locker(mutex);
			iterate_groups(func, priv);
		}

		void next_group(dnet_id &id, complete_func func, void *priv)
		{
			cb.clear();
			int err = dnet_lookup_object(sess.get_native(), &id, 0, func, priv);
			if (err) {
				throw_error(err, kid, "Failed to lookup ID");
			}
		}

		void finish(boost::exception_ptr exc)
		{
			if (exc) {
				handler(lookup_result(exc));
			} else {
				lookup_result_entry result = cb.any_result<lookup_result_entry>();
				dnet_convert_addr_attr(result.address_attribute());
				dnet_convert_file_info(result.file_info());
				handler(result);
			}
		}

		bool at_iterator;
		session sess;
		default_callback cb;
		size_t index;
		dnet_id id;
		key kid;
		std::vector<int> groups;
		boost::recursive_mutex mutex;
		boost::function<void (const lookup_result &)> handler;
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

		void finish(boost::exception_ptr exc)
		{
			if (exc)
				handler(exc);
			else
				handler(results());
		}

		session sess;
		dnet_trans_control ctl;
		boost::recursive_mutex mutex;
		boost::function<void (const callback_result &)> handler;
};

template <typename T>
void check_for_exception(const T &result)
{
	if (result.exception())
		boost::rethrow_exception(result.exception());
}

template <typename T>
void check_for_exception(const std::vector<T> &result)
{
	if (result.empty())
		throw_error(-ENOENT, "No data available");
	else if (result[0].exception())
		boost::rethrow_exception(result[0].exception());
}

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
		boost::exception_ptr exc_ptr;
		try {
			boost::recursive_mutex::scoped_lock locker(ptr->mutex);
			finish = ptr->handle(state, cmd, handler, priv);
		} catch (std::exception &exc) {
			exc_ptr = boost::copy_exception(exc);
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
