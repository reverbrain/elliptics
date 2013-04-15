#pragma once
#include <elliptics/module_backend/cpp/uncomplicated_handler.hpp>
#include <elliptics/module_backend/cpp/honest_command_handler.hpp>
#include <elliptics/module_backend/core/module_backend_api_t.h>
#include <elliptics/module_backend/core/module_backend_config_t.h>
#include <elliptics/interface.h>
#include <memory>

namespace ioremap {
namespace elliptics {

module_backend_api_t * setup_handler(std::unique_ptr<honest_command_handler> honest_command_handler);
module_backend_api_t * setup_handler(std::unique_ptr<uncomplicated_handler> uncomplicated_handler);

template<typename T>
T decorate_exception(std::function<T()> function, const T &error_value)
{
	try {
		return function();
	} catch (const std::exception &e) {
		report_module_backend_error(e.what());
	} catch (...) {
		report_module_backend_error("Unknown exception: ...");
	}
	return error_value;
}

}
}
