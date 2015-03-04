/*
 * Copyright 2013+ Ruslan Nigmatullin <euroelessar@yandex.ru>
 *
 * This file is part of Elliptics.
 *
 * Elliptics is free software: you can redistribute it and/or modify
 * it under the terms of the GNU Lesser General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 *
 * Elliptics is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU Lesser General Public License for more details.
 *
 * You should have received a copy of the GNU Lesser General Public License
 * along with Elliptics.  If not, see <http://www.gnu.org/licenses/>.
 */

#include "../../include/elliptics/result_entry.hpp"
#include "../../include/elliptics/session.hpp"

#include <condition_variable>
#include <mutex>
#include <queue>

namespace ioremap { namespace elliptics {

template <typename T>
class async_result<T>::data
{
	public:
		data() : total(0), finished(false)
		{
			dnet_current_time(&start);
			dnet_empty_time(&end);
		}

		std::mutex lock;
		std::condition_variable condition;

		async_result<T>::result_function result_handler;
		async_result<T>::final_function final_handler;

		result_filter filter;
		result_checker checker;
		uint32_t policy;
		result_error_handler error_handler;

		std::vector<T> results;
		error_info error;

		std::vector<dnet_cmd> statuses;
		size_t total;

		bool finished;
		dnet_time start;
		dnet_time end;
};

template <typename T>
async_result<T>::async_result()
{
}

template <typename T>
async_result<T>::async_result(const session &sess) : m_data(std::make_shared<data>())
{
	m_data->filter = sess.get_filter();
	m_data->checker = sess.get_checker();
	m_data->policy = sess.get_exceptions_policy();
	m_data->error_handler = sess.get_error_handler();
}

template <typename T>
async_result<T>::async_result(async_result &&other) ELLIPTICS_NOEXCEPT
{
	std::swap(other.m_data, m_data);
}

template <typename T>
async_result<T> &async_result<T>::operator =(async_result &&other) ELLIPTICS_NOEXCEPT
{
	std::swap(other.m_data, m_data);
	return *this;
}

template <typename T>
async_result<T>::~async_result()
{
}

template <typename T>
bool async_result<T>::is_valid() const
{
	return !!m_data;
}

template <typename T>
void async_result<T>::connect(const result_function &result_handler, const final_function &final_handler)
{
	std::unique_lock<std::mutex> locker(m_data->lock);
	if (result_handler) {
		m_data->result_handler = result_handler;
		if (!m_data->results.empty()) {
			for (auto it = m_data->results.begin(), end = m_data->results.end(); it != end; ++it) {
				result_handler(*it);
			}
		}
	}
	if (final_handler) {
		m_data->final_handler = final_handler;
		if (m_data->finished)
			final_handler(m_data->error);
	}
}

template <typename T>
void async_result<T>::connect(const result_array_function &handler)
{
	auto keeper = std::make_shared<data_keeper>();
	keeper->data_ptr = m_data;
	connect(result_function(), std::bind(aggregator_final_handler, keeper, handler));
}

template <typename T>
void async_result<T>::connect(const async_result_handler<T> &handler)
{
	connect(std::bind(handler_process, handler, std::placeholders::_1),
		std::bind(handler_complete, handler, std::placeholders::_1));
}

template <typename T>
void async_result<T>::wait()
{
	wait(session::throw_at_wait);
}

template <typename T>
error_info async_result<T>::error() const
{
	return m_data->error;
}

template <typename T>
bool async_result<T>::ready() const
{
	return m_data->finished;
}

template <typename T>
size_t async_result<T>::total() const
{
	return m_data->total;
}

template <typename T>
dnet_time async_result<T>::start_time() const {
	return m_data->start;
}

template <typename T>
dnet_time async_result<T>::end_time() const {
	return m_data->end;
}

template <typename T>
dnet_time async_result<T>::elapsed_time() const
{
	dnet_time end;
	if (ready())
		end = m_data->end;
	else
		dnet_current_time(&end);

	end.tsec -= m_data->start.tsec;
	if (end.tnsec < m_data->start.tnsec) {
		static const uint64_t sec = 1000 * 1000 * 1000;
		end.tnsec += sec - m_data->start.tnsec;
		end.tsec -= 1;
	} else {
		end.tnsec -= m_data->start.tnsec;
	}

	return end;
}


template <typename T>
std::vector<T> async_result<T>::get()
{
	wait(session::throw_at_get);
	return m_data->results;
}

template <typename T>
bool async_result<T>::get(T &entry)
{
	wait(session::throw_at_get);
	for (auto it = m_data->results.begin(); it != m_data->results.end(); ++it) {
		if (it->status() == 0 && !it->data().empty()) {
			entry = *it;
			return true;
		}
	}
	return false;
}

template <>
bool async_result<index_entry>::get(index_entry &entry)
{
	wait(session::throw_at_get);
	if (!m_data->results.empty()) {
		entry = m_data->results[0];
		return true;
	}
	return false;
}

template <>
bool async_result<find_indexes_result_entry>::get(find_indexes_result_entry &entry)
{
	wait(session::throw_at_get);
	if (!m_data->results.empty()) {
		entry = m_data->results[0];
		return true;
	}
	return false;
}

/*!
 * \brief Waits for async result for get_index_metadata and sets it to output parameter \a entry
 * \param entry Output parameter where result will be placed
 * \return Returns true iff result was successfully obtained
 */
template <>
bool async_result<get_index_metadata_result_entry>::get(get_index_metadata_result_entry &entry)
{
	wait(session::throw_at_get);
	if (!m_data->results.empty()) {
		entry.index_size = 0;
		entry.is_valid = true;
		entry.shard_id = -1;
		for (auto it = m_data->results.begin(); it != m_data->results.end(); ++it) {
			if (it->is_valid) {
				entry.index_size += it->index_size;
			} else {
				entry.is_valid = false;
				return false;
			}
		}
		return true;
	}
	return false;
}

template <typename T>
T async_result<T>::get_one()
{
	T result;
	get(result);
	return result;
}

template <typename T>
async_result<T>::operator std::vector<T> ()
{
	return get();
}

template <typename T>
class async_result<T>::iterator::data
{
	public:
		std::mutex mutex;
		std::condition_variable condition;
		std::queue<T> results;
		uint32_t policy;
		bool finished;
		error_info error;
};

template <typename T>
async_result<T>::iterator::iterator() : m_state(data_at_end)
{
}

template <typename T>
async_result<T>::iterator::iterator(async_result &result) : d(std::make_shared<data>()), m_state(data_waiting)
{
	d->finished = false;
	d->policy = result.m_data->policy;
	result.connect(std::bind(process, d, std::placeholders::_1),
	std::bind(complete, d, std::placeholders::_1));
}

template <typename T>
async_result<T>::iterator::iterator(const iterator &other) : d(other.d)
{
	other.ensure_data();
	m_state = other.m_state;
	m_result = other.m_result;
}

template <typename T>
async_result<T>::iterator::~iterator()
{
}

template <typename T>
typename async_result<T>::iterator &async_result<T>::iterator::operator =(const iterator &other)
{
	other.ensure_data();
	m_state = other.m_state;
	m_result = other.m_result;
	return *this;
}

template <typename T>
bool async_result<T>::iterator::operator ==(const iterator &other) const
{
	return at_end() == other.at_end();
}

template <typename T>
bool async_result<T>::iterator::operator !=(const iterator &other) const
{
	return !operator ==(other);
}

template <typename T>
T async_result<T>::iterator::operator *() const
{
	ensure_data();
	if (m_state == data_at_end) {
		throw_error(-ENOENT, "async_result::iterator::operator *(): end iterator");
	}
	return m_result;
}

template <typename T>
T *async_result<T>::iterator::operator ->() const
{
	ensure_data();
	if (m_state == data_at_end) {
		throw_error(-ENOENT, "async_result::iterator::operator ->(): end iterator");
	}
	return &m_result;
}

template <typename T>
typename async_result<T>::iterator &async_result<T>::iterator::operator ++()
{
	ensure_data();
	if (m_state == data_at_end) {
		throw_error(-ENOENT, "async_result::iterator::operator ++(): end iterator");
	}
	m_state = data_waiting;
	ensure_data();
	return *this;
}

template <typename T>
typename async_result<T>::iterator async_result<T>::iterator::operator ++(int)
{
	ensure_data();
	iterator tmp = *this;
	++(*this);
	return tmp;
}

template <typename T>
bool async_result<T>::iterator::at_end() const
{
	ensure_data();
	return m_state == data_at_end;
}

template <typename T>
void async_result<T>::iterator::ensure_data() const
{
	if (m_state == data_waiting) {
		std::unique_lock<std::mutex> locker(d->mutex);
		while (!d->finished && d->results.empty())
			d->condition.wait(locker);

		if (d->results.empty()) {
			m_state = data_at_end;
			if (d->policy & session::throw_at_iterator_end)
				d->error.throw_error();
		} else {
			m_state = data_ready;
			m_result = d->results.front();
			d->results.pop();
		}
	}
}

template <typename T>
void async_result<T>::iterator::process(const std::weak_ptr<data> &weak_data, const T &result)
{
	if (std::shared_ptr<data> d = weak_data.lock()) {
		std::unique_lock<std::mutex> locker(d->mutex);
		d->results.push(result);
		d->condition.notify_all();
	}
}

template <typename T>
void async_result<T>::iterator::complete(const std::weak_ptr<data> &weak_data, const error_info &error)
{
	if (std::shared_ptr<data> d = weak_data.lock()) {
		std::unique_lock<std::mutex> locker(d->mutex);
		d->finished = true;
		d->error = error;
		d->condition.notify_all();
	}
}

template <typename T>
struct async_result<T>::data_keeper
{
	typedef std::shared_ptr<data_keeper> ptr;

	std::shared_ptr<data> data_ptr;
};

template <typename T>
void async_result<T>::wait(uint32_t policy)
{
	std::unique_lock<std::mutex> locker(m_data->lock);
	while (!m_data->finished)
		m_data->condition.wait(locker);
	if (m_data->policy & policy)
		m_data->error.throw_error();
}

template <typename T>
void async_result<T>::aggregator_final_handler(const std::shared_ptr<data_keeper> &keeper, const result_array_function &handler)
{
	std::shared_ptr<data> d;
	std::swap(d, keeper->data_ptr);
	handler(d->results, d->error);
}

template <typename T>
void async_result<T>::handler_process(async_result_handler<T> handler, const T &result)
{
	handler.process(result);
}

template <typename T>
void async_result<T>::handler_complete(async_result_handler<T> handler, const error_info &error)
{
	handler.complete(error);
}

template <typename T>
async_result_handler<T>::async_result_handler(const async_result<T> &result)
	: m_data(result.m_data)
{
}

template <typename T>
async_result_handler<T>::async_result_handler(const async_result_handler &other)
	: m_data(other.m_data)
{
}

template <typename T>
async_result_handler<T>::~async_result_handler()
{
}

template <typename T>
async_result_handler<T> &async_result_handler<T>::operator =(const async_result_handler &other)
{
	m_data = other.m_data;
	return *this;
}

template <typename T>
void async_result_handler<T>::set_total(size_t total)
{
	m_data->total = total;
}

template <typename T>
size_t async_result_handler<T>::get_total()
{
	return m_data->total;
}

template <typename T>
void async_result_handler<T>::process(const T &result)
{
	std::unique_lock<std::mutex> locker(m_data->lock);
	const dnet_cmd *cmd = result.command();
	if (!(cmd->flags & DNET_FLAGS_MORE))
		m_data->statuses.push_back(*cmd);
	if (!m_data->filter(result))
		return;
	if (m_data->result_handler) {
		m_data->result_handler(result);
	} else {
		m_data->results.push_back(result);
	}
}

template <>
void async_result_handler<index_entry>::process(const index_entry &result)
{
	std::unique_lock<std::mutex> locker(m_data->lock);
	if (m_data->result_handler) {
		m_data->result_handler(result);
	} else {
		m_data->results.push_back(result);
	}
}

template <>
void async_result_handler<find_indexes_result_entry>::process(const find_indexes_result_entry &result)
{
	std::unique_lock<std::mutex> locker(m_data->lock);
	if (m_data->result_handler) {
		m_data->result_handler(result);
	} else {
		m_data->results.push_back(result);
	}
}

/*!
 * \brief Processes index metadata if result_handler is set or saves metadata into async_result array
 * \param result Index metadata
 */
template <>
void async_result_handler<get_index_metadata_result_entry>::process(const get_index_metadata_result_entry &result)
{
	std::unique_lock<std::mutex> locker(m_data->lock);
	if (m_data->result_handler) {
		m_data->result_handler(result);
	} else {
		m_data->results.push_back(result);
	}
}

template <typename T>
void async_result_handler<T>::complete(const error_info &error)
{
	std::unique_lock<std::mutex> locker(m_data->lock);
	m_data->finished = true;
	dnet_current_time(&m_data->end);
	m_data->error = error;
	if (!error) {
		if (!check(&m_data->error))
			m_data->error_handler(m_data->error, m_data->statuses);
	}
	if (m_data->final_handler) {
		m_data->final_handler(m_data->error);
	}
	m_data->condition.notify_all();
}

template <typename T>
bool async_result_handler<T>::check(error_info *error)
{
	if (!m_data->checker(m_data->statuses, m_data->total)) {
		if (error) {
			size_t success = 0;
			dnet_cmd command;
			command.status = 0;
			for (auto it = m_data->statuses.begin(); it != m_data->statuses.end(); ++it) {
				const bool failed_to_send = !(it->flags & DNET_FLAGS_REPLY);
				const bool ignore_error = failed_to_send && it->status == -ENXIO;

				if (it->status == 0) {
					++success;
				} else if (command.status == 0 && !ignore_error) {
					command = *it;
				}
			}
			if (success == 0 && command.status) {
				*error = create_error(command);
			} else {
				*error = create_error(-ENXIO, "insufficient results count due to checker: "
						"%zu of %zu (%zu)",
					success, m_data->total, m_data->statuses.size());
			}
		}
		return false;
	}
	if (error)
		*error = error_info();
	return true;
}

template <>
bool async_result_handler<index_entry>::check(error_info *error)
{
	if (error)
		*error = error_info();
	return true;
}

template <>
bool async_result_handler<find_indexes_result_entry>::check(error_info *error)
{
	if (error)
		*error = error_info();
	return true;
}

/*!
 * \brief Checks whether async_result was correctly obtained
 * \param error Out parameter filled with error_info if error occured during obtaining async_result
 * \return Returns true iff no error occured during obtaining async_result
 */
template <>
bool async_result_handler<get_index_metadata_result_entry>::check(error_info *error)
{
	if (error)
		*error = error_info();
	return true;
}

template class async_result<callback_result_entry>;
template class async_result<read_result_entry>;
template class async_result<lookup_result_entry>;
template class async_result<monitor_stat_result_entry>;
template class async_result<backend_status_result_entry>;
template class async_result<exec_result_entry>;
template class async_result<iterator_result_entry>;
template class async_result<index_entry>;
template class async_result<find_indexes_result_entry>;
template class async_result<get_index_metadata_result_entry>;

template class async_result_handler<callback_result_entry>;
template class async_result_handler<read_result_entry>;
template class async_result_handler<lookup_result_entry>;
template class async_result_handler<monitor_stat_result_entry>;
template class async_result_handler<backend_status_result_entry>;
template class async_result_handler<exec_result_entry>;
template class async_result_handler<iterator_result_entry>;
template class async_result_handler<index_entry>;
template class async_result_handler<find_indexes_result_entry>;
template class async_result_handler<get_index_metadata_result_entry>;

} }
