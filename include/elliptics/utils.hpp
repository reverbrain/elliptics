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

#include "elliptics/error.hpp"

namespace ioremap { namespace elliptics {

class data_buffer
{
	public:
		data_buffer(size_t capacity = 0)
			: m_data(0)
			, m_size(0)
			, m_capacity(capacity)
		{
		}

		data_buffer(const char *buf, size_t len) :
			m_data(0),
			m_size(len),
			m_capacity(len)
		{
			m_data = (char *)::malloc(len);
			if (!m_data)
				throw std::bad_alloc();
			::memcpy(m_data, buf, len);
		}

		data_buffer(data_buffer &&other) :
			m_data(other.m_data),
			m_size(other.m_size),
			m_capacity(other.m_capacity)
		{
			other.m_data = NULL;
			other.m_size = 0;
		}

		~data_buffer()
		{
			::free(m_data);
		}

		data_buffer &operator =(data_buffer &&other)
		{
			std::swap(m_data, other.m_data);
			std::swap(m_size, other.m_size);
			std::swap(m_capacity, other.m_capacity);

			return *this;
		}

		template<typename T>
		void write(T ob, typename std::enable_if<std::is_pod<T>::value >::type* = 0) {
			write(reinterpret_cast<const char*>(&ob), sizeof(T));
		}

		void write(const char *buf, size_t len)
		{
			check(len);
			::memcpy(m_data + m_size, buf, len);
			m_size += len;
		}

		void *release()
		{
			void *res = m_data;
			m_data = 0;
			m_size = 0;
			return res;
		}

		size_t size()
		{
			return m_size;
		}

	private:
		data_buffer(const data_buffer &) = delete;
		data_buffer &operator = (const data_buffer &) = delete;

		void check(size_t len)
		{
			if ((m_size + len) <= m_capacity)
			{
				if (!m_data) {
					m_data = (char *)::malloc(m_capacity);
					if (!m_data)
						throw std::bad_alloc();
				}
				return;
			}

			size_t nsize = m_capacity ? m_capacity : 16;
			while(nsize < (m_size + len))
				nsize *= 2;

			void *tmp = ::realloc(m_data, nsize);
			if(!tmp)
				throw std::bad_alloc();

			m_data = (char *)tmp;
			m_capacity = nsize;
		}

		char *m_data;
		size_t m_size;
		size_t m_capacity;
};

class data_pointer
{
	public:
		data_pointer() : m_index(0), m_size(0) {}

		data_pointer(void *data, size_t size)
			: m_data(std::make_shared<wrapper>(data)), m_index(0), m_size(size)
		{
		}

		data_pointer(const std::string &str)
			: m_data(std::make_shared<wrapper>(const_cast<char*>(str.c_str()), false)),
			m_index(0), m_size(str.size())
		{
		}

		data_pointer(data_buffer &&buf)
			: m_index(0), m_size(buf.size())
		{
			m_data = std::make_shared<wrapper>(buf.release());
		}

		static data_pointer copy(const void *data, size_t size)
		{
			data_pointer that = allocate(size);
			memcpy(that.data(), data, size);
			return that;
		}

		static data_pointer copy(const data_pointer &other)
		{
			return copy(other.data(), other.size());
		}

		static data_pointer copy(const std::string &other)
		{
			return copy(other.c_str(), other.size());
		}

		static data_pointer allocate(size_t size)
		{
			void *data = malloc(size);
			if (!data)
				throw std::bad_alloc();
			return data_pointer(data, size);
		}

		static data_pointer from_raw(void *data, size_t size)
		{
			data_pointer pointer;
			pointer.m_index = 0;
			pointer.m_size = size;
			pointer.m_data =  std::make_shared<wrapper>(data, false);
			return pointer;
		}

		static data_pointer from_raw(const std::string &str)
		{
			return from_raw(const_cast<char*>(str.c_str()), str.size());
		}

		template <typename T>
		data_pointer skip() const
		{
			data_pointer tmp(*this);
			tmp.m_index += sizeof(T);
			return tmp;
		}

		data_pointer skip(size_t size) const
		{
			data_pointer tmp(*this);
			tmp.m_index += size;
			return tmp;
		}

		data_pointer slice(size_t offset, size_t size) const
		{
			data_pointer tmp(*this);
			tmp.m_index += offset;
			tmp.m_size = tmp.m_index + size;
			return tmp;
		}

		void *data() const
		{
			if (m_index > m_size)
				throw not_found_error("null pointer exception");
			else if (m_index == m_size)
				return NULL;
			else
				return reinterpret_cast<char*>(m_data->get()) + m_index;
		}

		template <typename T>
		T *data() const
		{
			if (m_index + sizeof(T) > m_size)
				throw not_found_error("null pointer exception");
			return reinterpret_cast<T *>(data());
		}

		size_t size() const { return m_index >= m_size ? 0 : (m_size - m_index); }
		size_t offset() const { return m_index; }
		bool empty() const { return m_index >= m_size; }
		std::string to_string() const { return std::string(reinterpret_cast<char*>(data()), size()); }

	private:
		class wrapper
		{
			public:
				inline wrapper(void *data, bool owner = true) : data(data), owner(owner) {}
				inline ~wrapper() { if (owner && data) free(data); }

				inline void *get() const { return data; }

			private:
				void *data;
				bool owner;
		};

		std::shared_ptr<wrapper> m_data;
		size_t m_index;
		size_t m_size;
};

}} /* namespace ioremap::elliptics */

#endif // ELLIPTICS_UTILS_HPP
