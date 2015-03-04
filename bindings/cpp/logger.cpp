#include <elliptics/logger.hpp>
#include <elliptics/session.hpp>
#include "../../library/elliptics.h"
#include <stdarg.h>

#include "node_p.hpp"

// For BigBang
#include <blackhole/repository.hpp>

#include <blackhole/sink/files.hpp>
#include <blackhole/formatter/string.hpp>
#include <blackhole/frontend/files.hpp>

#include <boost/io/ios_state.hpp>

__thread trace_id_t backend_trace_id_hook;

namespace ioremap { namespace elliptics {

typedef blackhole::sink::files_t<
    blackhole::sink::files::boost_backend_t,
    blackhole::sink::rotator_t<
        blackhole::sink::files::boost_backend_t,
        blackhole::sink::rotation::watcher::move_t
    >
> elliptics_file_t;

file_logger::file_logger(const char *file, log_level level)
{
	verbosity(level);

	auto formatter = blackhole::utils::make_unique<blackhole::formatter::string_t>(format());
	formatter->set_mapper(file_logger::mapping());
	auto sink = blackhole::utils::make_unique<elliptics_file_t>(elliptics_file_t::config_type(file));
	auto frontend = blackhole::utils::make_unique
		<blackhole::frontend_t<blackhole::formatter::string_t, elliptics_file_t>>
			(std::move(formatter), std::move(sink));

	add_frontend(std::move(frontend));

	add_attribute(keyword::request_id() = 0);
}

std::string file_logger::format()
{
	return "%(timestamp)s %(request_id)s/%(lwp)s/%(pid)s %(severity)s: %(message)s, attrs: [%(...L)s]";
}

static const char *severity_names[] = {
	"debug",
	"notice",
	"info",
	"warning",
	"error"
};
static const size_t severity_names_count = sizeof(severity_names) / sizeof(severity_names[0]);

std::string file_logger::generate_level(log_level level)
{
	typedef blackhole::aux::underlying_type<log_level>::type level_type;
	auto value = static_cast<level_type>(level);

	if (value < 0 || value >= static_cast<level_type>(severity_names_count)) {
		return "unknown";
	}

	return severity_names[value];
}

log_level file_logger::parse_level(const std::string &name)
{
	auto it = std::find(severity_names, severity_names + severity_names_count, name);
	if (it == severity_names + severity_names_count) {
		throw std::logic_error("Unknown log level: " + name);
	}

	return static_cast<log_level>(it - severity_names);
}

static void format_request_id(blackhole::aux::attachable_ostringstream &out, uint64_t request_id)
{
	boost::io::ios_flags_saver ifs(out);
	out << std::setw(16) << std::setfill('0') << std::hex << request_id;
}

struct localtime_formatter_action {
    blackhole::aux::datetime::generator_t generator;

    localtime_formatter_action(const std::string &format) :
	generator(blackhole::aux::datetime::generator_factory_t::make(format))
    {
    }

    void operator() (blackhole::aux::attachable_ostringstream &stream, const timeval &value) const
    {
	std::tm tm;
	localtime_r(&value.tv_sec, &tm);
	generator(stream, tm, value.tv_usec);
    }
};

blackhole::mapping::value_t file_logger::mapping()
{
	blackhole::mapping::value_t mapper;
	mapper.add<blackhole::keyword::tag::timestamp_t>(localtime_formatter_action("%Y-%m-%d %H:%M:%S.%f"));
	mapper.add<keyword::tag::request_id_t>(format_request_id);
	mapper.add<blackhole::keyword::tag::severity_t<log_level>>(blackhole::defaults::map_severity);
	return mapper;
}

}} // namespace ioremap::elliptics

dnet_logger *dnet_node_get_logger(struct dnet_node *node)
{
	return node->log;
}

namespace blackhole_scoped_attributes {

enum {
	DNET_SCOPED_LIMIT = 5
};

static __thread char scoped_buffer[DNET_SCOPED_LIMIT][sizeof(blackhole::scoped_attributes_t)];
static __thread blackhole::scoped_attributes_t *scoped_attributes[DNET_SCOPED_LIMIT];
static __thread uint64_t scoped_trace_id_hook[DNET_SCOPED_LIMIT];
static __thread size_t scoped_count = 0;

}

void dnet_node_set_trace_id(dnet_logger *logger, uint64_t trace_id, int tracebit, int backend_id)
{
	using blackhole::scoped_attributes_t;
	using namespace blackhole_scoped_attributes;

	if (scoped_count >= DNET_SCOPED_LIMIT) {
		dnet_log_only_log(logger, DNET_LOG_ERROR,
			"logic error: you must not call dnet_node_set_trace_id twice, dnet_node_unset_trace_id call missed");
		++scoped_count;
		return;
	}

	auto &local_attributes = scoped_attributes[scoped_count];
	local_attributes = reinterpret_cast<scoped_attributes_t *>(scoped_buffer[scoped_count]);

	scoped_trace_id_hook[scoped_count] = tracebit ? ~0ull : 0;

	try {
		blackhole::log::attributes_t attributes = {
			ioremap::elliptics::keyword::request_id() = trace_id,
			blackhole::keyword::tracebit() = bool(tracebit)
		};

		if (backend_id >= 0) {
			attributes.insert(std::make_pair(std::string("backend_id"), blackhole::log::attribute_t(backend_id)));
		}

		new (local_attributes) scoped_attributes_t(*logger, std::move(attributes));

		// Set all bits to ensure that it has tracebit set
		backend_trace_id_hook = scoped_trace_id_hook[scoped_count];
	} catch (...) {
		local_attributes = NULL;
	}

	++scoped_count;
}

void dnet_node_unset_trace_id()
{
	using namespace blackhole_scoped_attributes;

	--scoped_count;

	if (scoped_count < DNET_SCOPED_LIMIT) {
		auto &local_attributes = scoped_attributes[scoped_count];
		local_attributes->~scoped_attributes_t();
		local_attributes = NULL;

		if (scoped_count > 0)
			backend_trace_id_hook = scoped_trace_id_hook[scoped_count - 1];
		else
			backend_trace_id_hook = 0;
	}
}

static __thread char dnet_logger_record_buffer[sizeof(dnet_logger_record)];

dnet_logger_record *dnet_log_open_record(dnet_logger *logger, dnet_log_level level)
{
	dnet_logger_record *record = reinterpret_cast<dnet_logger_record *>(dnet_logger_record_buffer);

	try {
		new (record) blackhole::log::record_t(logger->open_record(level));
	} catch (...) {
		return NULL;
	}

	if (!record->valid()) {
		record->~record_t();
		return NULL;
	}
	return record;
}

int dnet_log_enabled(dnet_logger *logger, dnet_log_level level)
{
	dnet_logger_record *record = reinterpret_cast<dnet_logger_record *>(dnet_logger_record_buffer);
	try {
		new (record) blackhole::log::record_t(logger->open_record(level));
		int result = record->valid();
		record->~record_t();
		return result;
	} catch (...) {
		return 0;
	}
}

dnet_log_level dnet_log_get_verbosity(dnet_logger *logger)
{
	return logger->log().verbosity();
}

void dnet_log_set_verbosity(dnet_logger *logger, dnet_log_level level)
{
	logger->log().verbosity(level);
}

static void dnet_log_add_message(dnet_logger_record *record, const char *format, va_list args)
{
	char buffer[2048];
	const size_t buffer_size = sizeof(buffer);

	vsnprintf(buffer, buffer_size, format, args);

	buffer[buffer_size - 1] = '\0';

	size_t len = strlen(buffer);
	while (len > 0 && buffer[len - 1] == '\n')
		buffer[--len] = '\0';

	try {
		record->attributes.insert(blackhole::keyword::message() = buffer);
	} catch (...) {
	}
}

void dnet_log_vwrite(dnet_logger *logger, dnet_logger_record *record, const char *format, va_list args)
{
	dnet_log_add_message(record, format, args);

	logger->push(std::move(*record));
}

void dnet_log_write(dnet_logger *logger, dnet_logger_record *record, const char *format, ...)
{
	va_list args;
	va_start(args, format);
	dnet_log_add_message(record, format, args);
	va_end(args);

	logger->push(std::move(*record));
}

void dnet_log_write_err(dnet_logger *logger, dnet_logger_record *record, int err, const char *format, ...)
{
	(void) err;

	va_list args;
	va_start(args, format);
	dnet_log_add_message(record, format, args);
	va_end(args);

	logger->push(std::move(*record));
}

void dnet_log_close_record(dnet_logger_record *record)
{
	record->~record_t();
}


void dnet_log_record_set_request_id(dnet_logger_record *record, uint64_t trace_id, int tracebit)
{
	try {
		record->attributes.insert(ioremap::elliptics::keyword::request_id() = trace_id);
		record->attributes.insert(blackhole::keyword::tracebit() = tracebit);
	} catch (...) {
	}
}
