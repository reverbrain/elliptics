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
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
 * GNU Lesser General Public License for more details.
 */

#ifndef IOREMAP_ELLIPTICS_ASYNC_RESULT_HPP
#define IOREMAP_ELLIPTICS_ASYNC_RESULT_HPP

#include "error.hpp"

#include <functional>
#include <vector>
#include <memory>

namespace ioremap { namespace elliptics {

template <typename T> class async_result_handler;
class session;

/*!
 * async_result is a template class that provides result of request processing.
 *
 * It provides both synchronious and asynchronious ways of usage.
 *
 * Synchronious is provided by wait/get methods and iterator API.
 *
 * Asynchronious is provided by connect methods.
 */
template <typename T>
class async_result
{
	ELLIPTICS_DISABLE_COPY(async_result)
	public:
		typedef async_result_handler<T> handler;
		typedef T entry_type;
		typedef std::function<void (const T &)> result_function;
		typedef std::function<void (const std::vector<T> &, const error_info &error)> result_array_function;
		typedef std::function<void (const error_info &)> final_function;

		/*!
		 * \brief Constructs invalid async_result.
		 */
		async_result();
		/*!
		 * Constructs async_result from session.
		 *
		 * At this point such session properties as filter, checker and exception policy
		 * are inherited from session.
		 */
		explicit async_result(const session &sess);

		/*!
		 * Constructs async_result by moving data from \a other.
		 */
		async_result(async_result &&other) ELLIPTICS_NOEXCEPT;
		/*!
		 * \brief Move operator from \a other async_result.
		 */
		async_result &operator =(async_result &&other) ELLIPTICS_NOEXCEPT;

		/*!
		 * Destroys async_result.
		 */
		~async_result();

		/*!
		 * \brief Returns if async_result is valid.
		 *
		 * It's usually becomes invalid after move operation.
		 */
		bool is_valid() const;

		/*!
		 * Connects receiving of data to callbacks.
		 *
		 * \a result_handler is invoked at every receiving entry.
		 * \a final_handler is invoked after the last entry is received, or when it's known
		 * that there will be no entries after (in case of error like timeout).
		 */
		void connect(const result_function &result_handler, const final_function &final_handler);

		/*!
		 * Connects receiving of data to callback.
		 *
		 * \a handler after the last entry is received or when it's known
		 * that there will be no entries after (in case of error like timeout).
		 *
		 * The list of all received entries in their receiving order is passed to
		 * handler as first argument.
		 * The second argument is error_info structure, which contains the information
		 * about the error if it is.
		 */
		void connect(const result_array_function &handler);

		/*!
		 * Connects receiving of data to callback.
		 *
		 * All receiving entries are passed to \a handler as is.
		 */
		void connect(const async_result_handler<T> &handler);

		/*!
		 * Blocks current thread until all entries are received.
		 *
		 * If session::throw_at_wait flag is activated and there were errors
		 * during procession the request the exception is thrown.
		 */
		void wait();

		/*!
		 * Returns the information about the error.
		 */
		error_info error() const;

		/*!
		 * Returns true if complete and false otherwise
		 */
		 bool ready() const;

		 /*!
		  * Returnes expected number of received positive final replies from server.
		  *
		  * This number is used afterwards in session::checker to determine if
		  * operation was successfull.
		  */
		 size_t total() const;

		 /*!
		  * Returns timestamp when async_result was created
		  */
		 dnet_time start_time() const;

		 /*!
		  * Returns timestamp when async_result was finished
		  * or empty time if it hasn't been finished yet
		  */
		 dnet_time end_time() const;

		/*!
		 * Returns time elapsed on execution
		 */
		 dnet_time elapsed_time() const;

		/*!
		 * Blocks current thread until all entries are received, then
		 * returns all of them as list.
		 *
		 * If session::throw_at_get flag is activated and there were errors
		 * during procession the request the exception is thrown.
		 */
		std::vector<T> get();


		/*!
		 * Blocks current thread until all entries are received, then
		 * first positive entry is set to \a entry.
		 *
		 * Returns true if there is at least one positive entry.
		 *
		 * If session::throw_at_get flag is activated and there were errors
		 * during procession the request the exception is thrown.
		 */
		bool get(T &entry);

		/*!
		 * Blocks current thread until all entries are received.
		 *
		 * Returns one positive entry.
		 *
		 * If session::throw_at_get flag is activated and there were errors
		 * during procession the request the exception is thrown.
		 */
		T get_one();

		/*!
		 * Implicit converstion to std::vector<T>.
		 *
		 * It's good practive to use async_result like this:
		 * \code
		 * sync_write_result result = sess.write_data(...);
		 * \endcode
		 *
		 * Blocks current thread until all entries are received.
		 *
		 * If session::throw_at_get flag is activated and there were errors
		 * during procession the request the exception is thrown.
		 */
		operator std::vector<T> ();

		/*!
		 * async_result provides STL-like input iterator.
		 *
		 * \note iterator doesn't store already processed data, so make sure to store it itself if needed.
		 */
		class iterator : public std::iterator<std::input_iterator_tag, T, std::ptrdiff_t, T*, T>
		{
			private:
				enum data_state {
					data_waiting,
					data_ready,
					data_at_end
				};
				class data;

			public:
				iterator();
				iterator(async_result &result);
				iterator(const iterator &other);
				~iterator();

				iterator &operator =(const iterator &other);

				bool operator ==(const iterator &other) const;
				bool operator !=(const iterator &other) const;

				T operator *() const;
				T *operator ->() const;

				iterator &operator ++();
				iterator operator ++(int);

			private:
				bool at_end() const;
				void ensure_data() const;
				static void process(const std::weak_ptr<data> &weak_data, const T &result);
				static void complete(const std::weak_ptr<data> &weak_data, const error_info &error);

				std::shared_ptr<data> d;
				mutable data_state m_state;
				mutable T m_result;
		};

		/*!
		 * Returns an STL-style iterator pointing to the first \em not processed item in the async_result.
		 *
		 * \note Iterator doesn't store already processed data, so make sure to store it itself if needed.
		 */
		iterator begin()
		{
			return iterator(*this);
		}

		/*!
		 * Returns an STL-style iterator pointing after the last item in the async_result.
		 */
		iterator end()
		{
			return iterator();
		}

	private:
		class data;

		struct data_keeper;

		void wait(uint32_t policy);

		static void aggregator_final_handler(const std::shared_ptr<data_keeper> &keeper, const result_array_function &handler);
		static void handler_process(async_result_handler<T> handler, const T &result);
		static void handler_complete(async_result_handler<T> handler, const error_info &error);

		friend class iterator;
		template <typename K> friend class async_result_handler;
		std::shared_ptr<data> m_data;
};

/*!
 * \internal
 *
 * It's used to provide entries to async_result.
 */
template <typename T>
class async_result_handler
{
	public:
		async_result_handler(const async_result<T> &result);
		async_result_handler(const async_result_handler &other);
		~async_result_handler();

		async_result_handler &operator =(const async_result_handler &other);

		void set_total(size_t total);
		size_t get_total();
		void process(const T &result);
		void complete(const error_info &error);
		bool check(error_info *error);

	private:
		typedef typename async_result<T>::data data;
		std::shared_ptr<data> m_data;
};

}} /* namespace ioremap::elliptics */

#endif // IOREMAP_ELLIPTICS_ASYNC_RESULT_HPP
