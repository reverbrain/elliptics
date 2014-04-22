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

#ifndef ELLIPTICS_UTILS_HPP
#define ELLIPTICS_UTILS_HPP

#include <memory>
#include <type_traits>
#include <cstring>
#include <cstdlib>
#include <type_traits>

#if __GNUC__ == 4 && __GNUC_MINOR__ < 5
#  include <cstdatomic>
#else
#  include <atomic>
#endif

#include "elliptics/error.hpp"

namespace ioremap { namespace elliptics {

template <typename atomic_type, bool Mutable>
class data_pointer_base;

template <typename AtomicType>
class data_buffer_base
{
	public:
		typedef AtomicType atomic_type;

		data_buffer_base(size_t capacity = 0) :
			m_data(0),
			m_size(0),
			m_capacity(capacity)
		{
		}

		data_buffer_base(const char *buf, size_t len) :
			m_data(0),
			m_size(len),
			m_capacity(len)
		{
			m_data = reinterpret_cast<char *>(std::malloc(sizeof(atomic_type) + len));
			if (!m_data) {
				throw std::bad_alloc();
			}
			std::memcpy(m_data + sizeof(atomic_type), buf, len);
		}

		data_buffer_base(data_buffer_base &&other) :
			m_data(other.m_data),
			m_size(other.m_size),
			m_capacity(other.m_capacity)
		{
			other.m_data = NULL;
			other.m_size = 0;
		}

		~data_buffer_base()
		{
			std::free(m_data);
		}

		data_buffer_base &operator =(data_buffer_base &&other)
		{
			std::swap(m_data, other.m_data);
			std::swap(m_size, other.m_size);
			std::swap(m_capacity, other.m_capacity);

			return *this;
		}

		template<typename T>
		void write(const T &ob, typename std::enable_if<std::is_pod<T>::value >::type* = 0)
		{
			write(reinterpret_cast<const char*>(&ob), sizeof(T));
		}

		void write(const void *buf, size_t len)
		{
			check(len);
			std::memcpy(m_data + sizeof(atomic_type) + m_size, buf, len);
			m_size += len;
		}

		size_t size() const
		{
			return m_size;
		}

	private:
		data_buffer_base(const data_buffer_base &) = delete;
		data_buffer_base &operator = (const data_buffer_base &) = delete;

		void check(size_t len)
		{
			if ((m_size + sizeof(atomic_type) + len) <= m_capacity) {
				if (!m_data) {
					m_data = reinterpret_cast<char *>(::malloc(m_capacity));
					if (!m_data)
						throw std::bad_alloc();
				}
				return;
			}

			size_t nsize = m_capacity ? m_capacity : 16;
			while (nsize < (m_size + sizeof(atomic_type) + len)) {
				nsize *= 2;
			}

			void *tmp = std::realloc(m_data, nsize);
			if (!tmp) {
				throw std::bad_alloc();
			}

			m_data = reinterpret_cast<char *>(tmp);
			m_capacity = nsize;
		}

		template <typename AtomicClass, bool Mutable> friend class data_pointer_base;

		char *m_data;
		size_t m_size;
		size_t m_reserved;
		size_t m_capacity;
};

template <typename AtomicType, bool Mutable>
class data_pointer_base
{
	template <typename T>
	struct fix_const
	{
		typedef typename std::conditional<Mutable,
			typename std::remove_const<T>::type,
			typename std::add_const<T>::type>::type type;
	};
	public:
		typedef AtomicType atomic_type;

		data_pointer_base() : m_counter(NULL), m_data(NULL), m_index(0), m_size(0)
		{
		}

		data_pointer_base(data_buffer_base<atomic_type> &&buf) : m_index(0), m_size(buf.size())
		{
			m_counter = new (buf.m_data) atomic_type(1);
			m_data = buf.m_data + sizeof(atomic_type);
			buf.m_data = NULL;
			buf.m_size = 0;
		}

		data_pointer_base(const data_pointer_base &other) :
			m_counter(other.m_counter), m_data(other.m_data),
			m_index(other.m_index), m_size(other.m_size)
		{
			if (m_counter)
				++(*m_counter);
		}

		data_pointer_base(data_pointer_base &&other) :
			m_counter(other.m_counter), m_data(other.m_data),
			m_index(other.m_index), m_size(other.m_size)
		{
			other.m_counter = NULL;
			other.m_data = NULL;
			other.m_index = 0;
			other.m_size = 0;
		}

		data_pointer_base &operator =(const data_pointer_base &other)
		{
			data_pointer_base tmp(other);
			swap(tmp);
			return *this;
		}

		data_pointer_base &operator =(data_pointer_base &&other)
		{
			swap(other);
			return *this;
		}

		~data_pointer_base()
		{
			if (m_counter && --(*m_counter) == 0) {
				m_counter->~atomic_type();
				free(m_counter);
			}
		}

		static data_pointer_base copy(const void *data, size_t size)
		{
			data_pointer_base that = allocate(size);
			memcpy(that.data(), data, size);
			return that;
		}

		static data_pointer_base copy(const data_pointer_base &other)
		{
			return copy(other.data(), other.size());
		}

		static data_pointer_base copy(const std::string &other)
		{
			return copy(other.c_str(), other.size());
		}

		static data_pointer_base allocate(size_t size)
		{
			char *data = reinterpret_cast<char *>(malloc(sizeof(atomic_type) + size));
			if (!data)
				throw std::bad_alloc();

			try {
				new (data) atomic_type(1);
			} catch (...) {
				free(data);
				throw;
			}

			data_pointer_base tmp;
			tmp.m_counter = reinterpret_cast<atomic_type *>(data);
			tmp.m_data = data + sizeof(atomic_type);
			tmp.m_size = size;

			return tmp;
		}

		static data_pointer_base from_raw(void *data, size_t size)
		{
			data_pointer_base pointer;
			pointer.m_data = data;
			pointer.m_size = size;
			return pointer;
		}

		static data_pointer_base from_raw(const std::string &str)
		{
			return from_raw(const_cast<char*>(str.c_str()), str.size());
		}

		template <typename T>
		data_pointer_base skip() const
		{
			data_pointer_base tmp(*this);
			tmp.m_index += sizeof(T);
			return tmp;
		}

		data_pointer_base skip(size_t size) const
		{
			data_pointer_base tmp(*this);
			tmp.m_index += size;
			return tmp;
		}

		data_pointer_base slice(size_t offset, size_t size) const
		{
			data_pointer_base tmp(*this);
			tmp.m_index += offset;
			tmp.m_size = std::min(m_size, tmp.m_index + size);
			return tmp;
		}

		typename fix_const<void>::type *data() const
		{
			if (m_index > m_size)
				throw not_found_error("null pointer exception");
			else if (m_index == m_size)
				return NULL;
			else
				return reinterpret_cast<typename fix_const<char *>::type>(m_data) + m_index;
		}

		template <typename T>
		typename fix_const<T>::type *data() const
		{
			if (m_index + sizeof(T) > m_size)
				throw not_found_error("null pointer exception");
			return reinterpret_cast<typename fix_const<T>::type *>(data());
		}

		void swap(data_pointer_base &other)
		{
			using std::swap;
			swap(m_counter, other.m_counter);
			swap(m_data, other.m_data);
			swap(m_index, other.m_index);
			swap(m_size, other.m_size);
		}

		size_t size() const { return m_index >= m_size ? 0 : (m_size - m_index); }
		size_t offset() const { return m_index; }
		bool empty() const { return m_index >= m_size; }
		std::string to_string() const { return std::string(reinterpret_cast<const char *>(data()), size()); }

	private:
		atomic_type *m_counter;
		typename fix_const<void>::type *m_data;
		size_t m_index;
		size_t m_size;
};

template <typename AtomicType>
class argument_data_base
{
public:
    typedef AtomicType atomic_type;
    typedef data_pointer_base<atomic_type, true> pointer_type;

	argument_data_base(const pointer_type &data) :
		m_data(data)
	{
	}

	argument_data_base(const std::string &data) :
		m_data(pointer_type::from_raw(data))
	{
	}

	template <ssize_t size>
	argument_data_base(const char (&data)[size], typename std::enable_if<size >= 1, char *>::type = NULL) :
		m_data(pointer_type::from_raw(const_cast<char *>(data), size - 1))
	{
	}

	argument_data_base(const char *data) :
		m_data(pointer_type::from_raw(const_cast<char *>(data), std::strlen(data)))
	{
	}

	const void *data() const
	{
		return m_data.data();
	}

	size_t size() const
	{
		return m_data.size();
	}

private:
	data_pointer_base<atomic_type, true> m_data;
};

typedef data_pointer_base<std::atomic_int_fast32_t, true> data_pointer;
typedef argument_data_base<std::atomic_int_fast32_t> argument_data;
typedef data_buffer_base<std::atomic_int_fast32_t> data_buffer;

}} /* namespace ioremap::elliptics */

#endif // ELLIPTICS_UTILS_HPP
