#ifndef __IOREMAP_LOGGER_HPP
#define __IOREMAP_LOGGER_HPP

#include <stdarg.h>
#include <stdint.h>

#ifdef __cplusplus
#ifndef BOOST_BIND_NO_PLACEHOLDERS
# define BOOST_BIND_NO_PLACEHOLDERS
# define BOOST_BIND_NO_PLACEHOLDERS_SET_BY_ELLIPTICS
#endif
#ifndef BLACKHOLE_HEADER_ONLY
# define BLACKHOLE_HEADER_ONLY
#endif

#include <blackhole/log.hpp>
#include <blackhole/logger/wrapper.hpp>
#include <blackhole/formatter/map/value.hpp>
#include <blackhole/defaults/severity.hpp>

#ifdef BOOST_BIND_NO_PLACEHOLDERS_SET_BY_ELLIPTICS
# undef BOOST_BIND_NO_PLACEHOLDERS_SET_BY_ELLIPTICS
# undef BOOST_BIND_NO_PLACEHOLDERS
#endif

#define DNET_LOG_ERROR blackhole::defaults::severity::error
#define DNET_LOG_WARNING blackhole::defaults::severity::warning
#define DNET_LOG_INFO blackhole::defaults::severity::info
#define DNET_LOG_NOTICE blackhole::defaults::severity::notice
#define DNET_LOG_DEBUG blackhole::defaults::severity::debug

namespace ioremap { namespace elliptics {

typedef blackhole::defaults::severity log_level;
typedef blackhole::verbose_logger_t<log_level> logger_base;
typedef blackhole::wrapper_t<logger_base> logger;

class file_logger : public logger_base
{
public:
	explicit file_logger(const char *file, log_level level);

	static std::string format();
	static std::string generate_level(log_level level);
	static log_level parse_level(const std::string &name);
	static blackhole::mapping::value_t mapping();
};

DECLARE_LOCAL_KEYWORD(dnet_id, std::string)
DECLARE_EVENT_KEYWORD(request_id, uint64_t)

} }

typedef ioremap::elliptics::logger dnet_logger;
typedef blackhole::log::record_t dnet_logger_record;
typedef ioremap::elliptics::log_level dnet_log_level;

#define ELLIPTICS_LOG_LEVEL ioremap::elliptics::log_level

extern "C" {
#else
typedef struct cpp_ioremap_elliptics_logger dnet_logger;
typedef struct cpp_blackhole_log_record_t dnet_logger_record;

// Keep in sync with blackhole::defaults::severity
enum dnet_log_level {
	DNET_LOG_DEBUG,
	DNET_LOG_NOTICE,
	DNET_LOG_INFO,
	DNET_LOG_WARNING,
	DNET_LOG_ERROR
};

#define ELLIPTICS_LOG_LEVEL enum dnet_log_level

#endif

struct dnet_node;

dnet_logger *dnet_node_get_logger(struct dnet_node *node);
void dnet_node_set_trace_id(dnet_logger *logger, uint64_t trace_id, int tracebit, int backend_id);
void dnet_node_unset_trace_id();
dnet_logger_record *dnet_log_open_record(dnet_logger *logger, ELLIPTICS_LOG_LEVEL level);
void dnet_log_record_set_request_id(dnet_logger_record *record, uint64_t trace_id, int tracebit);
int dnet_log_enabled(dnet_logger *logger, ELLIPTICS_LOG_LEVEL level);
ELLIPTICS_LOG_LEVEL dnet_log_get_verbosity(dnet_logger *logger);
void dnet_log_set_verbosity(dnet_logger *logger, ELLIPTICS_LOG_LEVEL level);
void dnet_log_vwrite(dnet_logger *logger, dnet_logger_record *record, const char *format, va_list args);
void dnet_log_write(dnet_logger *logger, dnet_logger_record *record, const char *format, ...) __attribute__ ((format(printf, 3, 4)));
void dnet_log_write_err(dnet_logger *logger, dnet_logger_record *record, int err, const char *format, ...) __attribute__ ((format(printf, 4, 5)));
void dnet_log_close_record(dnet_logger_record *record);

#undef ELLIPTICS_LOG_LEVEL

#ifdef __cplusplus
}

#endif

#endif // __IOREMAP_LOGGER_HPP
