#pragma once

#include <elliptics/module_backend.h>
#include <elliptics/packet.h>
#include <elliptics/interface.h>
#include <string>
#include <memory>

namespace ioremap {
namespace elliptics {

/**
 * This is C++ binding for elliptics module with "AS IS" interface.
 * You can derive from it to implement elliptics module.
 * Also you can use @a uncomplicated_handler in favor of simplicity.
 */
class honest_command_handler {
public:
	virtual int file_write(module_backend_t *r, void *state, dnet_cmd *cmd, void *data)=0;
	virtual int file_read(module_backend_t *r, void *state, dnet_cmd *cmd, void *data)=0;
	virtual int file_info(module_backend_t *r, void *state, dnet_cmd *cmd)=0;
	virtual int file_del(module_backend_t *r, void *state, dnet_cmd *cmd)=0;
	virtual int file_bulk_read(module_backend_t *r, void *state, dnet_cmd *cmd, void *data)=0;
	virtual int file_iterator(struct dnet_iterator_ctl *ictl, struct dnet_iterator_request *ireq, struct dnet_iterator_range *irange)=0;
	virtual ~honest_command_handler() {};
};

/**
 * This is abstract class for simple (aka uncomplicated) interface
 * of elliptics module. This class must be used if you don't interested
 * in internal elliptics structres, and just want to make it work fast.
 */
class uncomplicated_handler {
public:
    /**
     * This function should implement reading data by key
     */
	virtual std::string read(const std::string &key)=0;
	virtual ~uncomplicated_handler() {};
};

module_backend_api_t * setup_handler(dnet_logger *log, std::unique_ptr<honest_command_handler> honest_command_handler);
module_backend_api_t * setup_handler(dnet_logger *log, std::unique_ptr<uncomplicated_handler> uncomplicated_handler);

template<typename T>
T decorate_exception(dnet_logger *log, std::function<T()> function, const T &error_value)
{
	try {
		return function();
	} catch (const std::exception &e) {
		report_module_backend_error(log, e.what());
	} catch (...) {
		report_module_backend_error(log, "Unknown exception: ...");
	}
	return error_value;
}

}
}
