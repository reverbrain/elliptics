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

file_logger::file_logger(const char *file, int level)
{
	verbosity(static_cast<dnet_log_level>(level));
	track(false);

	auto formatter = blackhole::utils::make_unique<blackhole::formatter::string_t>(format());
	formatter->set_mapper(file_logger::mapping());
	auto sink = blackhole::utils::make_unique<blackhole::sink::files_t<>>(blackhole::sink::files_t<>::config_type(file));
	auto frontend = blackhole::utils::make_unique<blackhole::frontend_t<blackhole::formatter::string_t, blackhole::sink::files_t<>>>(std::move(formatter), std::move(sink));

	add_frontend(std::move(frontend));

	add_attribute(blackhole::keyword::request_id() = 0);
}

std::string file_logger::format()
{
	return "%(timestamp)s %(request_id)s/%(lwp)s/%(pid)s %(severity)s: %(message)s, attrs: [%(...L)s]";
}

static void format_request_id(blackhole::aux::attachable_ostringstream &out, uint64_t request_id)
{
	boost::io::ios_flags_saver ifs(out);
	out << std::setw(16) << std::setfill('0') << std::hex << request_id;
}

blackhole::mapping::value_t file_logger::mapping()
{
	blackhole::mapping::value_t mapper;
	mapper.add<blackhole::keyword::tag::timestamp_t>("%Y-%m-%d %H:%M:%S.%f");
	mapper.add<blackhole::keyword::tag::request_id_t>(format_request_id);
	return mapper;
}

}} // namespace ioremap::elliptics

dnet_logger *dnet_node_get_logger(struct dnet_node *node)
{
	return node->log;
}

static __thread char blackhole_scoped_attributes_buffer[sizeof(blackhole::scoped_attributes_t)];
static __thread blackhole::scoped_attributes_t *blackhole_attributes = NULL;

void dnet_node_set_trace_id(dnet_logger *logger, uint64_t trace_id, int tracebit)
{
	using blackhole::scoped_attributes_t;

	if (blackhole_attributes) {
		dnet_log_only_log(logger, DNET_LOG_ERROR, "logic error: you must not call dnet_node_set_trace_id twice, dnet_node_unset_trace_id call missed");
		return;
	}

	blackhole_attributes = reinterpret_cast<scoped_attributes_t *>(blackhole_scoped_attributes_buffer);

	try {
		blackhole::log::attributes_t attributes = {
			blackhole::keyword::request_id() = trace_id,
			blackhole::keyword::tracebit() = bool(tracebit)
		};
		new (blackhole_attributes) scoped_attributes_t(*logger, std::move(attributes));
		// Set all bits to ensure that it has tracebit set
		backend_trace_id_hook = tracebit ? ~0ull : 0;
	} catch (...) {
		blackhole_attributes = NULL;
	}
}

void dnet_node_unset_trace_id()
{
	if (blackhole_attributes) {
		blackhole_attributes->~scoped_attributes_t();
		blackhole_attributes = NULL;
	}
	backend_trace_id_hook = 0;
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

enum dnet_log_level dnet_log_get_verbosity(dnet_logger *logger)
{
	return logger->log().verbosity();
}

void dnet_log_set_verbosity(dnet_logger *logger, enum dnet_log_level level)
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

	record->attributes.insert(blackhole::keyword::message() = buffer);
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
