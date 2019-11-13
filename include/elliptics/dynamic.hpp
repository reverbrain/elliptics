#pragma once
 
#include <cstdint>
#include <map>
#include <sstream>
#include <string>
#include <type_traits>
#include <unordered_map>
#include <vector>
 
#include <boost/any.hpp>
#include <boost/format.hpp>
#include <boost/variant.hpp>
#include <boost/numeric/conversion/cast.hpp>

namespace blackhole {

#define BLACKHOLE_NOEXCEPT noexcept
#define BLACKHOLE_API inline

namespace utils {
namespace aux {

static inline
std::string
substitute(boost::format&& message) {
    return message.str();
}

template<typename T, typename... Args>
static inline
std::string
substitute(boost::format&& message, const T& argument, const Args&... args) {
    return substitute(std::move(message % argument), args...);
}

} // namespace aux

template<typename... Args>
static inline
std::string
format(const std::string& format, const Args&... args) {
    try {
        return aux::substitute(boost::format(format), args...);
    } catch(const boost::io::format_error& e) {
        std::ostringstream stream;
        stream << "<unable to format the message - " << e.what() << ">";
        return stream.str();
    }
}

template<typename T, typename... Args>
std::unique_ptr<T> make_unique(Args&&... args) {
    return std::unique_ptr<T>(new T(std::forward<Args>(args)...));
}

} // namespace utils

namespace type_traits {

template<typename T>
struct is_integer :
    public std::conditional<
        std::is_integral<T>::value && !std::is_same<T, bool>::value,
        std::true_type,
        std::false_type
    >::type
{};

template<typename T>
struct is_unsigned_integer :
    public std::conditional<
        is_integer<T>::value && std::is_unsigned<T>::value,
        std::true_type,
        std::false_type
    >::type
{};

template<typename T>
struct is_signed_integer :
    public std::conditional<
        is_integer<T>::value && std::is_signed<T>::value,
        std::true_type,
        std::false_type
    >::type
{};

} // namespace type_traits

namespace conversion {

template<typename T, class Enable = void>
struct integer_t;

template<typename T>
struct integer_t<T, typename std::enable_if<type_traits::is_unsigned_integer<T>::value>::type> {
    typedef uint64_t type;
};

template<typename T>
struct integer_t<T, typename std::enable_if<type_traits::is_signed_integer<T>::value>::type> {
    typedef int64_t type;
};

} // namespace conversion

class dynamic_t {
public:
    struct null_t {
        bool operator==(const null_t&) const {
            return true;
        }
    };

    typedef bool                             bool_t;
    typedef int64_t                          int_t;
    typedef uint64_t                         uint_t;
    typedef double                           double_t;
    typedef std::string                      string_t;
    typedef std::vector<dynamic_t>           array_t;
    typedef std::map<std::string, dynamic_t> object_t;

    typedef boost::variant<
        null_t,
        bool_t,
        uint_t,
        int_t,
        double_t,
        string_t,
        array_t,
        object_t
    > value_type;

private:
    value_type value;

    template<typename T>
    struct is_convertible : public
        std::integral_constant<
            bool,
            std::is_convertible<dynamic_t::null_t,   T>::value ||
            std::is_convertible<dynamic_t::bool_t,   T>::value ||
            std::is_convertible<dynamic_t::uint_t,   T>::value ||
            std::is_convertible<dynamic_t::int_t,    T>::value ||
            std::is_convertible<dynamic_t::double_t, T>::value ||
            std::is_convertible<dynamic_t::string_t, T>::value ||
            std::is_convertible<dynamic_t::array_t,  T>::value ||
            std::is_convertible<dynamic_t::object_t, T>::value
        >
    {};

public:
    dynamic_t();
    dynamic_t(const dynamic_t& other);
    dynamic_t(dynamic_t&& other) BLACKHOLE_NOEXCEPT;

    dynamic_t(bool value);

    template<typename T>
    dynamic_t(T&& from,
              typename std::enable_if<
                  type_traits::is_integer<typename std::decay<T>::type>::value
              >::type* = 0);

    dynamic_t(double value);

    dynamic_t(const char* value);
    dynamic_t(std::string value);
    dynamic_t(array_t value);
    dynamic_t(object_t value);

    dynamic_t& operator=(const dynamic_t& other);
    dynamic_t& operator=(dynamic_t&& other) BLACKHOLE_NOEXCEPT;

    bool operator==(const dynamic_t& other) const;

    bool invalid() const;

    bool contains(const std::string& key) const;

    dynamic_t& operator[](array_t::size_type key);
    const dynamic_t& operator[](array_t::size_type key) const;
    dynamic_t& operator[](const std::string& key);
    const dynamic_t& operator[](const std::string& key) const;

    template<typename T>
    typename std::enable_if<
        is_convertible<T>::value,
        bool
    >::type
    is() const;

    template<typename T>
    typename std::enable_if<
        is_convertible<T>::value && !type_traits::is_integer<T>::value,
        T
    >::type
    to() const;

    template<typename T>
    typename std::enable_if<
        is_convertible<T>::value && type_traits::is_integer<T>::value,
        T
    >::type
    to() const;
};

namespace dynamic {

namespace visitor {

class name_t : public boost::static_visitor<std::string> {
public:
    std::string operator()(const dynamic_t::null_t&) const {
        return "null";
    }

    std::string operator()(const dynamic_t::bool_t&) const {
        return "bool";
    }

    std::string operator()(const dynamic_t::uint_t&) const {
        return "uint";
    }

    std::string operator()(const dynamic_t::int_t&) const {
        return "int";
    }

    std::string operator()(const dynamic_t::double_t&) const {
        return "double";
    }

    std::string operator()(const dynamic_t::string_t&) const {
        return "string";
    }

    std::string operator()(const dynamic_t::array_t&) const {
        return "array";
    }

    std::string operator()(const dynamic_t::object_t&) const {
        return "object";
    }
};

} // namespace visitor

class precision_loss : public std::out_of_range {
public:
    template<typename T>
    precision_loss(T actual,
                   const std::string& reason,
                   typename std::enable_if<
                       type_traits::is_integer<typename std::decay<T>::type>::value
                   >::type* = 0) :
        std::out_of_range(
            blackhole::utils::format(
                "unable to convert integer (%d) without precision loss: %s",
                actual,
                reason
            )
        )
    {}
};

class negative_overflow : public precision_loss {
public:
    template<typename T>
    negative_overflow(T actual) :
        precision_loss(actual, "negative overflow")
    {}
};

class positive_overflow : public precision_loss {
public:
    template<typename T>
    positive_overflow(T actual) :
        precision_loss(actual, "positive overflow")
    {}
};

class bad_cast : public std::logic_error {
public:
    bad_cast(const dynamic_t::value_type& value) :
        std::logic_error(
            blackhole::utils::format(
                "unable to convert dynamic type (underlying type is '%s')",
                boost::apply_visitor(dynamic::visitor::name_t(), value)
            )
        )
    {}
};

template<typename T, typename Actual>
static inline
typename std::enable_if<type_traits::is_integer<T>::value, T>::type
safe_cast(Actual actual) {
    try {
        return boost::numeric_cast<T>(actual);
    } catch (const boost::numeric::negative_overflow&) {
        throw dynamic::negative_overflow(actual);
    } catch (const boost::numeric::positive_overflow&) {
        throw dynamic::positive_overflow(actual);
    }
}

} // namespace dynamic

BLACKHOLE_API
dynamic_t::dynamic_t() :
    value(null_t())
{}

BLACKHOLE_API
dynamic_t::dynamic_t(const dynamic_t& other) :
    value(other.value)
{}

BLACKHOLE_API
dynamic_t::dynamic_t(dynamic_t&& other) BLACKHOLE_NOEXCEPT :
    value(std::move(other.value))
{
    other.value = null_t();
}

BLACKHOLE_API
dynamic_t::dynamic_t(bool value) :
    value(value)
{}

BLACKHOLE_API
dynamic_t::dynamic_t(double value) :
    value(value)
{}

BLACKHOLE_API
dynamic_t::dynamic_t(const char *value) :
    value(std::string(value))
{}

BLACKHOLE_API
dynamic_t::dynamic_t(std::string value) :
    value(std::move(value))
{}

BLACKHOLE_API
dynamic_t::dynamic_t(dynamic_t::array_t value) :
    value(std::move(value))
{}

BLACKHOLE_API
dynamic_t::dynamic_t(dynamic_t::object_t value) :
    value(std::move(value))
{}

template<typename T>
BLACKHOLE_API
dynamic_t::dynamic_t(T&& from,
                     typename std::enable_if<
                        type_traits::is_integer<typename std::decay<T>::type
                     >::value>::type*) :
    value(
        static_cast<
            typename conversion::integer_t<typename std::decay<T>::type>::type
        >(std::forward<T>(from))
    )
{}

BLACKHOLE_API
dynamic_t& dynamic_t::operator=(const dynamic_t& other) {
    this->value = other.value;
    return *this;
}

BLACKHOLE_API
dynamic_t& dynamic_t::operator=(dynamic_t&& other) BLACKHOLE_NOEXCEPT {
    this->value = std::move(other.value);
    other.value = null_t();
    return *this;
}

BLACKHOLE_API
bool dynamic_t::operator==(const dynamic_t& other) const {
    return value == other.value;
}

BLACKHOLE_API
bool dynamic_t::invalid() const {
    return is<null_t>();
}

BLACKHOLE_API
bool dynamic_t::contains(const std::string& key) const {
    auto object = to<object_t>();
    return object.find(key) != object.end();
}

BLACKHOLE_API
dynamic_t& dynamic_t::operator[](array_t::size_type key) {
    if (auto container = boost::get<array_t>(&value)) {
       if (key >= container->size()) {
           container->resize(key + 1);
       }
       return (*container)[key];
    }

    if (boost::get<null_t>(&value)) {
       value = array_t();
       return (*this)[key];
    }

    throw dynamic::bad_cast(value);
}

BLACKHOLE_API
const dynamic_t& dynamic_t::operator[](array_t::size_type key) const {
    if (auto container = boost::get<array_t>(&value)) {
       return container->at(key);
    }

    throw dynamic::bad_cast(value);
}

BLACKHOLE_API
dynamic_t& dynamic_t::operator[](const std::string& key) {
    if (auto map = boost::get<object_t>(&value)) {
        return (*map)[key];
    }

    if (boost::get<null_t>(&value)) {
        value = object_t();
        return (*this)[key];
    }

    throw dynamic::bad_cast(value);
}

BLACKHOLE_API
const dynamic_t& dynamic_t::operator[](const std::string &key) const {
    if (auto map = boost::get<object_t>(&value)) {
        return map->at(key);
    }

    throw dynamic::bad_cast(value);
}

template<typename T>
BLACKHOLE_API
typename std::enable_if<
    dynamic_t::is_convertible<T>::value,
    bool
>::type
dynamic_t::is() const {
    return boost::get<T>(&value) != nullptr;
}

template<typename T>
BLACKHOLE_API
typename std::enable_if<
    dynamic_t::is_convertible<T>::value && !type_traits::is_integer<T>::value,
    T
>::type
dynamic_t::to() const {
    if (auto result = boost::get<T>(&value)) {
        return *result;
    }

    throw dynamic::bad_cast(value);
}

template<typename T>
BLACKHOLE_API
typename std::enable_if<
    dynamic_t::is_convertible<T>::value && type_traits::is_integer<T>::value,
    T
>::type
dynamic_t::to() const {
    if (auto actual = boost::get<int_t>(&value)) {
        return dynamic::safe_cast<T>(*actual);
    }

    if (auto actual = boost::get<uint_t>(&value)) {
        return dynamic::safe_cast<T>(*actual);
    }

    throw dynamic::bad_cast(value);
}



} // namespace blackhole
