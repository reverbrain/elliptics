#pragma once
#include <elliptics/packet.h>
#include <elliptics/module_backend/core/module_backend_api_t.h>
extern "C" {
struct module_backend_t;
}


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
	virtual ~honest_command_handler();
};

}
}
