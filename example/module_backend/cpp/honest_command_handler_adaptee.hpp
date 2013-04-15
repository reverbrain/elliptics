#pragma once

#include <elliptics/module_backend/cpp/honest_command_handler.hpp>
#include <elliptics/module_backend/cpp/uncomplicated_handler.hpp>
#include <memory>

namespace ioremap {
namespace elliptics {

/**
 * This class is an backward adaptor ( i.e. adaptee ) from
 * @a honest_command_handler interface to @a uncomplicated_handler interface.
 */
class honest_command_handler_adaptee : public honest_command_handler {
public:
	honest_command_handler_adaptee(std::unique_ptr<uncomplicated_handler> uncomplicated_handler);
	virtual int file_write(module_backend_t *r, void *state, dnet_cmd *cmd, void *data);
	virtual int file_read(module_backend_t *r, void *state, dnet_cmd *cmd, void *data);
	virtual int file_info(module_backend_t *r, void *state, dnet_cmd *cmd);
private:
	std::unique_ptr<uncomplicated_handler> m_uncomplicated_handler;
};

}
}
