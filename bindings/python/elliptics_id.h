#ifndef ELLIPTICS_PYTHON_ELLIPTICS_ID_HPP
#define ELLIPTICS_PYTHON_ELLIPTICS_ID_HPP

#include <boost/python/list.hpp>

#include <elliptics/session.hpp>

namespace bp = boost::python;

namespace ioremap { namespace elliptics { namespace python {

class elliptics_id : public key {
public:
	elliptics_id();
	elliptics_id(const std::string &remote);
	elliptics_id(const dnet_id &id);
	elliptics_id(const dnet_raw_id &id);
	elliptics_id(const key &other);
	elliptics_id(const elliptics_id &other);
	elliptics_id(const bp::list &id, const uint32_t &group_id);

	bp::list get_id() const;

	void set_id(const bp::list &id);

	uint32_t group_id() const;

	void set_group_id(const uint32_t &group_id);

	int cmp(const elliptics_id &other) const;

	static elliptics_id convert(const bp::api::object &id);
	// Implements __str__ method.
	// Always returns printable hex representation of all id bytes
	std::string to_str() const;

	// Implements __repr__ method.
	// Returns group, hex id prefix, and original key string
	// (depending on key's previous history, any of those could be zero or empty).
	std::string to_repr() const;
};

void init_elliptcs_id();

} } } // namespace ioremap::elliptics::python

#endif // ELLIPTICS_PYTHON_ELLIPTICS_ID_HPP
