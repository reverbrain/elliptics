#include <elliptics/module_backend/cpp/registration.hpp>
#include <stdexcept>
#include <functional>
#include "honest_command_handler_adaptee.hpp"
#include "../core/module_backend_t.h"
#include <errno.h>

using namespace ioremap::elliptics;

namespace {

int dnet_module_db_write(void */*priv*/, dnet_raw_id */*id*/, void */*data*/, size_t /*size*/)
{
	return 0;
}

honest_command_handler * unwrap_private(module_backend_api_t *module_backend_api)
{
	return static_cast<honest_command_handler *>(module_backend_api->private_data);
}

honest_command_handler *unwrap_private(void *priv)
{
	return unwrap_private(static_cast<module_backend_t *>(priv)->api);
}

void destroy_module_backend(module_backend_api_t *module_backend_api)
{
	delete unwrap_private(module_backend_api);
	delete module_backend_api;
}

int command_handler_throw(void *state, void *priv, struct dnet_cmd *cmd, void *data)
{
	honest_command_handler *backend = unwrap_private(priv);
	struct module_backend_t *r = static_cast<module_backend_t *>(priv);
	switch (cmd->cmd) {
		case DNET_CMD_WRITE:
			backend->file_write(r, state, cmd, data);
			break;
		case DNET_CMD_LOOKUP:
			backend->file_info(r, state, cmd);
			break;
		case DNET_CMD_READ:
			backend->file_read(r, state, cmd, data);
			break;
		default:
			throw std::runtime_error("No such command");
			break;
	}
	return 0;
}

int command_handler(void *state, void *priv, struct dnet_cmd *cmd, void *data)
{
	return decorate_exception<int>(std::bind(&command_handler_throw, state, priv, cmd, data), -EINVAL);
}

int meta_write_handler(void *priv, struct dnet_raw_id *id, void *data, size_t size)
{
	return ::dnet_module_db_write(priv, id, data, size);
}

module_backend_api_t * setup_handler_throw(std::unique_ptr<uncomplicated_handler> &uncomplicated_handler)
{
	std::unique_ptr<honest_command_handler> honest_command_handler(new honest_command_handler_adaptee(std::move(uncomplicated_handler)));
	return setup_handler(std::move(honest_command_handler));
}

}

module_backend_api_t* ioremap::elliptics::setup_handler(std::unique_ptr<honest_command_handler> honest_command_handler)
{
	std::unique_ptr<module_backend_api_t> module_backend_api(new module_backend_api_t);
	module_backend_api->destroy_handler = destroy_module_backend;
	module_backend_api->command_handler = command_handler;
	module_backend_api->meta_write_handler = meta_write_handler;
	module_backend_api->private_data = honest_command_handler.release();
	return module_backend_api.release();
}

module_backend_api_t* ioremap::elliptics::setup_handler(
	std::unique_ptr<uncomplicated_handler> uncomplicated_handler
)
{
	std::function<module_backend_api_t *()> function = std::bind(&setup_handler_throw, std::ref(uncomplicated_handler));
	return decorate_exception<module_backend_api_t *>(function, NULL);
}
