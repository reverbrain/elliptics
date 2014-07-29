#ifndef LOGGER_HPP
#define LOGGER_HPP

#include <stdarg.h>
#include <stdint.h>

/*
 * Log level
 *
 * IT IS ALSO PROVIDED IN PYTHON BINDING so if you want to add new level
 * please also add it to elliptics_log_level and to BOOST_PYTHON_MODULE(core) in elliptics_python.cpp
 */
enum dnet_log_level {
	DNET_LOG_DATA = 0,
	DNET_LOG_ERROR,
	DNET_LOG_INFO,
	DNET_LOG_NOTICE,
	DNET_LOG_DEBUG,
};

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

#ifdef BOOST_BIND_NO_PLACEHOLDERS_SET_BY_ELLIPTICS
# undef BOOST_BIND_NO_PLACEHOLDERS_SET_BY_ELLIPTICS
# undef BOOST_BIND_NO_PLACEHOLDERS
#endif

namespace ioremap { namespace elliptics {

typedef blackhole::verbose_logger_t<dnet_log_level> logger_base;
typedef blackhole::wrapper_t<logger_base> logger;

class file_logger : public logger_base
{
public:
	explicit file_logger(const char *file, int level);

	static std::string format();
};

} }

typedef ioremap::elliptics::logger dnet_logger;
typedef blackhole::log::record_t dnet_logger_record;

extern "C" {
#else
typedef struct cpp_ioremap_elliptics_logger dnet_logger;
typedef struct cpp_blackhole_log_record_t dnet_logger_record;
#endif

struct dnet_node;

dnet_logger *dnet_node_get_logger(struct dnet_node *node);
void dnet_node_set_trace_id(dnet_logger *logger, uint64_t trace_id, int tracebit);
void dnet_node_unset_trace_id();
dnet_logger_record *dnet_log_open_record(dnet_logger *logger, enum dnet_log_level level);
int dnet_log_enabled(dnet_logger *logger, enum dnet_log_level level);
enum dnet_log_level dnet_log_get_verbosity(dnet_logger *logger);
void dnet_log_set_verbosity(dnet_logger *logger, enum dnet_log_level level);
void dnet_log_vwrite(dnet_logger *logger, dnet_logger_record *record, const char *format, va_list args);
void dnet_log_write(dnet_logger *logger, dnet_logger_record *record, const char *format, ...) __attribute__ ((format(printf, 3, 4)));
void dnet_log_write_err(dnet_logger *logger, dnet_logger_record *record, int err, const char *format, ...) __attribute__ ((format(printf, 4, 5)));
void dnet_log_close_record(dnet_logger_record *record);

#ifdef __cplusplus
}

#endif

#endif // LOGGER_HPP
