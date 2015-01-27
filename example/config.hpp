#ifndef CONFIG_HPP
#define CONFIG_HPP

#include <elliptics/error.hpp>
#include <blackhole/dynamic.hpp>
#include <blackhole/attribute.hpp>

#include <elliptics/session.hpp>
#include "../library/backend.h"
#include "../library/elliptics.h"
#include "../monitor/monitor.hpp"

namespace ioremap { namespace elliptics { namespace config {

class config_error : public std::exception
{
public:
	explicit config_error()
	{
	}

	config_error(const config_error &other) :
		m_message(other.m_message)
	{
		m_stream << m_message;
	}

	config_error &operator =(const config_error &other)
	{
		m_message = other.m_message;
		m_stream << m_message;
		return *this;
	}

	explicit config_error(const std::string &message)
	{
		m_stream << message;
		m_message = message;
	}

	const char *what() const ELLIPTICS_NOEXCEPT
	{
		return m_message.c_str();
	}

	template <typename T>
	config_error &operator <<(const T &value)
	{
		m_stream << value;
		m_message = m_stream.str();
		return *this;
	}

	config_error &operator <<(std::ostream &(*handler)(std::ostream &))
	{
		m_stream << handler;
		m_message = m_stream.str();
		return *this;
	}

	virtual ~config_error() throw()
	{}

private:
	std::stringstream m_stream;
	std::string m_message;
};


namespace detail
{

using blackhole::dynamic_t;

enum {
	boolean_type = 1,
	integral_type = 2,
	floating_point_type = 4,
	string_type = 8,
	vector_type = 16
};

template <typename T, int specific>
struct config_value_caster_specific_helper;

template <typename T>
struct is_vector : public std::false_type { };

template <typename T>
struct is_vector<std::vector<T>> : public std::true_type { };


template <typename T>
struct config_value_caster_helper
{
	enum {
		boolean = std::is_same<T, bool>::value ? boolean_type : 0,
		integral = std::is_integral<T>::value && !boolean ? integral_type : 0,
		floating_point = std::is_floating_point<T>::value ? floating_point_type : 0,
		string = std::is_same<T, std::string>::value ? string_type : 0,
		vector = is_vector<T>::value ? vector_type : 0,
		type = integral | floating_point | string | boolean | vector
	};

	static_assert(integral || floating_point || string || boolean || vector, "Unsupported type");
	static_assert((type == integral) || (type == floating_point) || (type == string) || (type == boolean) || (type == vector), "Internal type check error");

	static T cast(const std::string &path, const dynamic_t &value)
	{
		return config_value_caster_specific_helper<T, type>::cast(path, value);
	}
};

template <typename T>
struct config_value_caster : public config_value_caster_helper<typename std::remove_all_extents<T>::type>
{
};

template <typename T>
struct config_value_caster_specific_helper<T, boolean_type>
{
	static T cast(const std::string &path, const dynamic_t &value)
	{
		if (!value.is<dynamic_t::bool_t>())
			throw config_error() << path << " must be a bool";

		return value.to<dynamic_t::bool_t>();
	}
};

template <typename T>
struct config_value_caster_specific_helper<T, integral_type>
{
	static T cast(const std::string &path, const dynamic_t &value)
	{
		try {
			// dynamic_t has it's own built-in range check support
			// which throws precision_loss exception in case of error
			// so it's safe just to call dynamic_t::to here
			return value.to<T>();
		} catch (blackhole::dynamic::precision_loss &) {
			throw config_error() << path << " must be an integer between "
				<< std::numeric_limits<T>::min() << " and " << std::numeric_limits<T>::max();
		}
	}
};

template <typename T>
struct config_value_caster_specific_helper<T, floating_point_type>
{
	static T cast(const std::string &path, const dynamic_t &value)
	{
		if (!value.is<dynamic_t::double_t>())
			throw config_error() << path << " must be a floating point number";

		return value.to<dynamic_t::double_t>();
	}
};

template <typename T>
struct config_value_caster_specific_helper<T, string_type>
{
	static T cast(const std::string &path, const dynamic_t &value)
	{
		if (!value.is<dynamic_t::string_t>())
			throw config_error() << path << " must be a string";

		return value.to<dynamic_t::string_t>();
	}
};

template <typename T>
struct config_value_caster_specific_helper<T, vector_type>
{
	static T cast(const std::string &path, const dynamic_t &value)
	{
		typedef config_value_caster<typename T::value_type> caster;

		if (!value.is<dynamic_t::array_t>())
			throw config_error() << path << " must be an array";

		const dynamic_t::array_t &array = value.to<dynamic_t::array_t>();

		T result;
		for (size_t i = 0; i < array.size(); ++i)
			result.emplace_back(caster::cast(path + "[" + std::to_string(static_cast<long long int>(i)) + "]", array[i]));
		return result;
	}
};

}

class config
{
	typedef blackhole::dynamic_t dynamic_t;
public:
	config(const std::string &path, const dynamic_t &value) :
		m_path(path), m_value(value)
	{
	}

	bool has(const std::string &name) const
	{
		assert_object();

		return m_value.contains(name);
	}

	config at(const std::string &name) const
	{
		const std::string path = m_path + "." + name;
		if (!has(name))
			throw config_error() << path << " is missed";

		const dynamic_t::object_t &object = m_value.to<dynamic_t::object_t>();
		return config(path, object.find(name)->second);
	}

	template <typename T>
	T at(const std::string &name, const T &default_value) const
	{
		if (!has(name))
			return default_value;

		return at(name).as<T>();
	}

	template <typename T>
	T at(const std::string &name) const
	{
		return at(name).as<T>();
	}

	size_t size() const
	{
		assert_array();
		return m_value.to<const dynamic_t::array_t &>().size();
	}

	bool has(size_t index) const
	{
		return index < size();
	}

	config at(size_t index) const
	{
		const std::string path = m_path + "[" + std::to_string(static_cast<long long int>(index)) + "]";

		if (!has(index))
			throw config_error() << path << " is missed";

		return config(path, m_value[index]);
	}

	template <typename T>
	T at(size_t index, const T &default_value) const
	{
		if (!has(index))
			return default_value;

		return at(index).as<T>();
	}

	template <typename T>
	T at(size_t index) const
	{
		return at(index).as<T>();
	}

	template <typename T>
	T as() const
	{
		assert_valid();
		return detail::config_value_caster<T>::cast(m_path, m_value);
	}

	const std::string &path() const
	{
		return m_path;
	}

	std::string to_string() const
	{
		assert_valid();

		std::string value_str;

		if (m_value.is<dynamic_t::uint_t>())
			value_str = std::to_string(static_cast<unsigned long long>(m_value.to<dynamic_t::uint_t>()));
		else if (m_value.is<dynamic_t::int_t>())
			value_str = std::to_string(static_cast<long long>(m_value.to<dynamic_t::int_t>()));
		else if (m_value.is<dynamic_t::double_t>())
			value_str = std::to_string(static_cast<long double>(m_value.to<dynamic_t::double_t>()));
		else if (m_value.is<dynamic_t::string_t>())
			value_str = m_value.to<dynamic_t::string_t>();
		else
			throw config_error() << m_path << " has unknown type";

		return value_str;
	}

	void assert_valid() const
	{
		if (m_value.invalid())
			throw config_error() << m_path << " is missed";
	}

	void assert_array() const
	{
		assert_valid();
		if (!m_value.is<dynamic_t::array_t>())
			throw config_error() << m_path << " must be an array";
	}

	void assert_object() const
	{
		assert_valid();
		if (!m_value.is<dynamic_t::object_t>())
			throw config_error() << m_path << " must be an object";
	}

	const dynamic_t &raw() const
	{
		return m_value;
	}

protected:
	std::string m_path;
	const dynamic_t m_value;
};

class config_parser
{
public:
	config_parser();
	~config_parser();

	config open(const std::string &path);
	config root() const;
private:
	blackhole::dynamic_t root_;
};

struct config_data : public dnet_config_data
{
	config_data() : logger(logger_base, blackhole::log::attributes_t())
	{
		dnet_empty_time(&config_timestamp);
	}

	std::shared_ptr<config_parser> parse_config();

	std::string				config_path;
	std::mutex				parser_mutex;
	std::shared_ptr<config_parser>		parser;
	dnet_time				config_timestamp;
	dnet_backend_info_list			backends_guard;
	std::string				logger_value;
	ioremap::elliptics::logger_base		logger_base;
	ioremap::elliptics::logger		logger;
	std::vector<address>			remotes;
	std::unique_ptr<cache::cache_config>	cache_config;
	std::unique_ptr<monitor::monitor_config>	monitor_config;
};

} } } // namespace ioremap::elliptics::config

#endif // CONFIG_HPP
