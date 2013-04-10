#include "ModuleRegistration.h"
#include <stdexcept>
#include <functional>
#include "HonestCommandHandlerAdaptee.h"
#include "../example/module_backend/module_backend_t.h"

using namespace ioremap::elliptics;

const char* UNKNOWN_EXPLANATION("Unknown exception: ...");

namespace {

int dnet_module_db_write(void */*priv*/, dnet_raw_id */*id*/, void */*data*/, size_t /*size*/)
{
	return 0;
}

HonestCommandHandler* unwrap(module_backend_api_t* module_backend_api)
{
	return static_cast<HonestCommandHandler*>(module_backend_api->private_data);
}

HonestCommandHandler* unwrap(void* priv)
{
	return unwrap(static_cast<module_backend_t *>(priv)->api);
}

void destroy_module_backend(module_backend_api_t* module_backend_api)
{
	delete unwrap(module_backend_api);
	delete module_backend_api;
}

int command_handler_throw(void *state, void *priv, struct dnet_cmd *cmd, void *data)
{
	HonestCommandHandler* backend=unwrap(priv);
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
	return exception_filter<int>(std::bind(&command_handler_throw, state, priv, cmd, data), -EINVAL);
}

int meta_write_handler(void *priv, struct dnet_raw_id *id, void *data, size_t size)
{
	return ::dnet_module_db_write(priv, id, data, size);
}

module_backend_api_t* registerUncomplicatedBackendThrow(
	std::unique_ptr<UncomplicatedHandler> uncomplicatedHandler
)
{
	std::unique_ptr<HonestCommandHandler> honestCommandHandler(new HonestCommandHandlerAdaptee(std::move(uncomplicatedHandler)));
	return registerHonestCommandHandler(std::move(honestCommandHandler));
}

}

module_backend_api_t* ioremap::elliptics::registerHonestCommandHandler(
	std::unique_ptr<HonestCommandHandler> honestCommandHandler
)
{
	std::unique_ptr<module_backend_api_t> module_backend_api(new module_backend_api_t);
	module_backend_api->destroy_handler=destroy_module_backend;
	module_backend_api->command_handler=command_handler;
	module_backend_api->meta_write_handler=meta_write_handler;
	module_backend_api->private_data=honestCommandHandler.release();
	return module_backend_api.release();
}

namespace {
// http://stackoverflow.com/questions/4871273/passing-rvalues-through-stdbind
typedef std::unique_ptr<UncomplicatedHandler> Movable;
const auto hacky_cast=[](Movable& movable) {
	return std::bind([](Movable& movable){ return std::move(movable); }, std::ref(movable));
};
}

module_backend_api_t* ioremap::elliptics::registerUncomplicatedBackend(
	std::unique_ptr<UncomplicatedHandler> uncomplicatedHandler
)
{
	std::function<module_backend_api_t*()> function=std::bind(&registerUncomplicatedBackendThrow, hacky_cast(uncomplicatedHandler));
	return exception_filter<module_backend_api_t*>(function, NULL);
}
