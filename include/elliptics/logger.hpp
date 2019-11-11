#ifndef __IOREMAP_LOGGER_HPP
#define __IOREMAP_LOGGER_HPP

#include <stdarg.h>
#include <stdint.h>

enum dnet_log_level {
	DNET_LOG_DEBUG,
	DNET_LOG_NOTICE,
	DNET_LOG_INFO,
	DNET_LOG_WARNING,
	DNET_LOG_ERROR
};


#ifdef __cplusplus

#ifndef BOOST_BIND_NO_PLACEHOLDERS
# define BOOST_BIND_NO_PLACEHOLDERS
# define BOOST_BIND_NO_PLACEHOLDERS_SET_BY_ELLIPTICS
#endif
#ifndef BLACKHOLE_HEADER_ONLY
# define BLACKHOLE_HEADER_ONLY
#endif

#include <blackhole/attribute.hpp>
#include <blackhole/attributes.hpp>
#include <blackhole/config/json.hpp>
#include <blackhole/extensions/facade.hpp>
#include <blackhole/extensions/writer.hpp>
#include <blackhole/formatter.hpp>
#include <blackhole/formatter/string.hpp>
#include <blackhole/handler.hpp>
#include <blackhole/handler/blocking.hpp>
#include <blackhole/registry.hpp>
#include <blackhole/record.hpp>
#include <blackhole/root.hpp>
#include <blackhole/sink.hpp>
#include <blackhole/sink/console.hpp>
#include <blackhole/wrapper.hpp>

#ifdef BOOST_BIND_NO_PLACEHOLDERS_SET_BY_ELLIPTICS
# undef BOOST_BIND_NO_PLACEHOLDERS_SET_BY_ELLIPTICS
# undef BOOST_BIND_NO_PLACEHOLDERS
#endif

namespace ioremap { namespace elliptics {

static const char *severity_names[] = {
	"debug",
	"notice",
	"info",
	"warning",
	"error"
};
static const size_t severity_names_count = sizeof(severity_names) / sizeof(severity_names[0]);

static inline auto sevmap(std::size_t severity, const std::string& spec, blackhole::writer_t& writer) -> void {
    if (severity < severity_names_count) {
        writer.write(spec, severity_names[severity]);
    } else {
        writer.write(spec, severity);
    }
}

class logger_base : public blackhole::root_logger_t {
public:
	logger_base() : blackhole::root_logger_t(logger_base::default_logger()) {}
	logger_base(blackhole::root_logger_t &&other): blackhole::root_logger_t(std::move(other)) {}

	static blackhole::root_logger_t default_logger() {
		auto log = blackhole::builder<blackhole::root_logger_t>()
			.add(blackhole::builder<blackhole::handler::blocking_t>()
		     			.set(blackhole::builder<blackhole::formatter::string_t>("{severity}, [{timestamp}]: {message}")
			 			.mapping(&sevmap)
			 			.build())
		     			.add(blackhole::builder<blackhole::sink::console_t>()
				 		.build())
					.build())
			.build();
	    return std::move(*log);
	}
};

typedef blackhole::wrapper_t logger;

class file_logger : public logger_base
{
public:
	explicit file_logger(const char *file, dnet_log_level level);

	static std::string format();
	static dnet_log_level parse_level(const std::string &name);
};

}} // namespace ioremap::elliptics

typedef blackhole::record_t dnet_logger_record;
typedef ioremap::elliptics::logger dnet_logger;

extern "C" {
#else
typedef void dnet_logger;
typedef void dnet_logger_record;
#endif

typedef enum dnet_log_level dnet_log_level;

struct dnet_node;

dnet_logger *dnet_node_get_logger(struct dnet_node *node);
void dnet_node_set_trace_id(dnet_logger *logger, uint64_t trace_id, int tracebit, int backend_id);
void dnet_node_unset_trace_id();

int dnet_log_enabled(dnet_logger *logger, dnet_log_level level);
dnet_log_level dnet_log_get_verbosity(dnet_logger *logger);
void dnet_log_set_verbosity(dnet_logger *logger, dnet_log_level level);

void dnet_log_vwrite(dnet_logger *logger, int severity, const char *format, va_list args);
void dnet_log_write(dnet_logger *logger, int severity, const char *format, ...) __attribute__ ((format(printf, 3, 4)));
void dnet_log_write_err(dnet_logger *logger, int severity, int err, const char *format, ...) __attribute__ ((format(printf, 4, 5)));

#define dnet_logger_write(logger, severity, format, a...) dnet_log_write((dnet_logger *)&logger, severity, format, ##a)

#ifdef __cplusplus
}
#endif

#endif // __IOREMAP_LOGGER_HPP
