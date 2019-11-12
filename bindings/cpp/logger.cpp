#include <fstream>
#include <memory>

#include <elliptics/logger.hpp>
#include <elliptics/session.hpp>
#include "../../library/elliptics.h"
#include <stdarg.h>

#include "node_p.hpp"

#include <blackhole/formatter.hpp>
#include <blackhole/formatter/string.hpp>

__thread trace_id_t backend_trace_id_hook;

namespace ioremap { namespace elliptics {

file_logger::file_logger(const char *file, dnet_log_level level) :
	logger_base(std::move(blackhole::registry::configured()->builder<blackhole::config::json_t>(std::ifstream(file)).build("root")))
{
}

std::string file_logger::format()
{
	return "%(timestamp)s %(request_id)s/%(lwp)s/%(pid)s %(severity)s: %(message)s, attrs: [%(...L)s]";
}

dnet_log_level file_logger::parse_level(const std::string &name)
{
	auto it = std::find(severity_names, severity_names + severity_names_count, name);
	if (it == severity_names + severity_names_count) {
		throw std::logic_error("Unknown log level: " + name);
	}

	return static_cast<dnet_log_level>(it - severity_names);
}

#if 0
static void format_request_id(blackhole::aux::attachable_ostringstream &out, uint64_t request_id)
{
	boost::io::ios_flags_saver ifs(out);
	out << std::setw(16) << std::setfill('0') << std::hex << request_id;
}
#endif

}} // namespace ioremap::elliptics

dnet_logger *dnet_node_get_logger(struct dnet_node *node)
{
	return node->log;
}

namespace blackhole_scoped_attributes {

enum {
	DNET_SCOPED_LIMIT = 5
};

static __thread char scoped_buffer[DNET_SCOPED_LIMIT][sizeof(blackhole::attributes_t)];
static __thread blackhole::attributes_t *scoped_attributes[DNET_SCOPED_LIMIT];
static __thread uint64_t scoped_trace_id_hook[DNET_SCOPED_LIMIT];
static __thread size_t scoped_count = 0;

}

void dnet_node_set_trace_id(dnet_logger *logger, uint64_t trace_id, int tracebit, int backend_id)
{
	using blackhole::attributes_t;
	using namespace blackhole_scoped_attributes;

	if (scoped_count >= DNET_SCOPED_LIMIT) {
		dnet_log_write(logger, DNET_LOG_ERROR,
			"logic error: you may not call dnet_node_set_trace_id twice, dnet_node_unset_trace_id call missed");
		scoped_count++;
		return;
	}

	auto &local_attributes = scoped_attributes[scoped_count];
	local_attributes = reinterpret_cast<attributes_t *>(scoped_buffer[scoped_count]);

	scoped_trace_id_hook[scoped_count] = tracebit ? ~0ull : 0;

	try {
		blackhole::attributes_t attributes = {
			{"trace_id", trace_id},
			{"trace_bit", bool(tracebit)}
		};

		if (backend_id >= 0) {
			attributes.push_back({"backend_id", backend_id});
		}


		new (local_attributes) blackhole::attributes_t(std::move(attributes));

		// Set all bits to ensure that it has tracebit set
		backend_trace_id_hook = scoped_trace_id_hook[scoped_count];
	} catch (const std::exception &e) {
		dnet_log_write(logger, DNET_LOG_ERROR,
			"%s: trace_id: %08llx, tracebit: %d, backend_id: %d, caught exception: %s",
			__func__, (unsigned long long)trace_id, tracebit, backend_id, e.what());
	}

	// scoped_count has to be increased in any case, since it will be followed by
	// dnet_node_unset_trace_id() which doesn't know whether corresponding
	// dnet_node_set_trace_id() succeeded or not
	++scoped_count;
}

void dnet_node_unset_trace_id()
{
	using namespace blackhole_scoped_attributes;

	if (scoped_count > 0) {
		--scoped_count;

		if (scoped_count < DNET_SCOPED_LIMIT) {
			auto &local_attributes = scoped_attributes[scoped_count];
			typedef blackhole::attributes_t T;
			local_attributes->~T();
			local_attributes = NULL;

			if (scoped_count > 0)
				backend_trace_id_hook = scoped_trace_id_hook[scoped_count - 1];
			else
				backend_trace_id_hook = 0;

		}
	}
}

int dnet_log_enabled(dnet_logger *logger, dnet_log_level level)
{
	return 1;
}

dnet_log_level dnet_log_get_verbosity(dnet_logger *logger)
{
	return DNET_LOG_INFO;
}

void dnet_log_set_verbosity(dnet_logger *logger, dnet_log_level level)
{
}

void dnet_log_vwrite(dnet_logger *logger, int severity, const char *format, va_list args)
{
	char buffer[2048];
	const size_t buffer_size = sizeof(buffer);

	vsnprintf(buffer, buffer_size, format, args);

	buffer[buffer_size - 1] = '\0';

	size_t len = strlen(buffer);
	while (len > 0 && buffer[len - 1] == '\n')
		buffer[--len] = '\0';

	//logger->log(severity, buffer, blackhole::attribute_list{});
	logger->log(severity, buffer);
}

void dnet_log_write(dnet_logger *logger, int severity, const char *format, ...)
{
	va_list args;
	va_start(args, format);
	dnet_log_vwrite(logger, severity, format, args);
	va_end(args);
}

void dnet_logger_write(const dnet_logger &logger, int severity, const char *format, ...)
{
	va_list args;
	va_start(args, format);
	dnet_log_vwrite((dnet_logger *)&logger, severity, format, args);
	va_end(args);
}

void dnet_log_write_err(dnet_logger *logger, int err, const char *format, ...)
{
	(void) err;

	va_list args;
	va_start(args, format);
	dnet_log_vwrite(logger, DNET_LOG_ERROR, format, args);
	va_end(args);
}

void dnet_log(dnet_node *n, int severity, const char *format, ...)
{
	va_list args;
	va_start(args, format);
	dnet_log_vwrite(n->log, severity, format, args);
	va_end(args);
}
