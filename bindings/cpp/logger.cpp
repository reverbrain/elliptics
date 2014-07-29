#include <elliptics/logger.hpp>
#include <elliptics/session.hpp>
#include "../../library/elliptics.h"
#include <stdarg.h>

#include <blackhole/sink/files.hpp>
#include <blackhole/formatter/string.hpp>
#include <blackhole/frontend/files.hpp>

namespace ioremap { namespace elliptics {

file_logger::file_logger(const char *file, int level)
{
	verbosity(static_cast<dnet_log_level>(level));

	auto formatter = blackhole::utils::make_unique<blackhole::formatter::string_t>(format());
	auto sink = blackhole::utils::make_unique<blackhole::sink::files_t<>>(blackhole::sink::files_t<>::config_type(file));
	auto frontend = blackhole::utils::make_unique<blackhole::frontend_t<blackhole::formatter::string_t, blackhole::sink::files_t<>>>(std::move(formatter), std::move(sink));
	add_frontend(std::move(frontend));

	add_attribute(blackhole::keyword::request_id() = 0);
}

std::string file_logger::format()
{
	return "%(timestamp)s %(request_id)s/%(tid)s/%(pid)s %(severity)s: %(message)s %(...L)s";
}

}} // namespace ioremap::elliptics

dnet_logger *dnet_node_get_logger(struct dnet_node *node)
{
	return node->log;
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
