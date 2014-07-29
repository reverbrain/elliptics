#include <elliptics/module_backend.hpp>
#include <elliptics/cppdef.h>
#include <stdexcept>
#include <functional>
#include "honest_command_handler_adaptee.hpp"
#include "../core/module_backend_t.h"
#include <errno.h>

namespace ell = ioremap::elliptics;

namespace {

int dnet_module_db_write(void */*priv*/, dnet_raw_id */*id*/, void */*data*/, size_t /*size*/)
{
	return 0;
}

int dnet_module_db_remove(void */*priv*/, dnet_raw_id */*id*/, int /*real_remove*/)
{
	return 0;
}

ell::honest_command_handler * unwrap_private(module_backend_api_t *module_backend_api)
{
	return static_cast<ell::honest_command_handler *>(module_backend_api->private_data);
}

ell::honest_command_handler *unwrap_private(void *priv)
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
	ell::honest_command_handler *backend = unwrap_private(priv);
	struct module_backend_t *r = static_cast<module_backend_t *>(priv);
	int err = 0;
	
	switch (cmd->cmd) {
		case DNET_CMD_WRITE:
			err = backend->file_write(r, state, cmd, data);
			break;
		case DNET_CMD_LOOKUP:
			err = backend->file_info(r, state, cmd);
			break;
		case DNET_CMD_READ:
			err = backend->file_read(r, state, cmd, data);
			break;
		case DNET_CMD_DEL:
			err = backend->file_del(r, state, cmd);
			break;
		case DNET_CMD_BULK_READ:
			err = backend->file_bulk_read(r, state, cmd, data);
			break;
		default:
			ell::throw_error(-EINVAL, "No such command");
			break;
	}
	return err;
}

int iterator_throw(struct dnet_iterator_ctl *ictl, struct dnet_iterator_request *ireq, struct dnet_iterator_range *irange)
{
	ell::honest_command_handler *backend = unwrap_private(ictl->iterate_private);
	return backend->file_iterator(ictl, ireq, irange);
}

int decorate_elliptics_exception(std::function<int()> function)
{
	try {
		return function();
	} catch (const ell::error& e) {
		return e.error_code();
	}
}

int command_handler(void *state, void *priv, struct dnet_cmd *cmd, void *data)
{
	module_backend_t *r = static_cast<module_backend_t *>(priv);
	std::function<int()> handler = std::bind(command_handler_throw, state, priv, cmd, data);
	std::function<int()> decorated_handler = std::bind(decorate_elliptics_exception, handler);
	return ell::decorate_exception<int>(r->config.log, decorated_handler, -EINVAL);
}

int iterator(dnet_iterator_ctl *ictl, struct dnet_iterator_request *ireq, struct dnet_iterator_range *irange)
{
	module_backend_t *r = static_cast<module_backend_t *>(ictl->iterate_private);
	std::function<int()> handler = std::bind(iterator_throw, ictl, ireq, irange);
	std::function<int()> decorated_handler = std::bind(decorate_elliptics_exception, handler);
	return ell::decorate_exception<int>(r->config.log, decorated_handler, -EINVAL);
}

int meta_write_handler(void *priv, struct dnet_raw_id *id, void *data, size_t size)
{
	return ::dnet_module_db_write(priv, id, data, size);
}

int meta_remove_handler(void *priv, struct dnet_raw_id *id, int real_remove)
{
       return ::dnet_module_db_remove(priv, id, real_remove);
}

module_backend_api_t * setup_handler_throw(dnet_logger *log,
	std::unique_ptr<ell::uncomplicated_handler> &uncomplicated_handler)
{
	std::unique_ptr<ell::honest_command_handler> honest_command_handler(new ell::honest_command_handler_adaptee(std::move(uncomplicated_handler)));
	return setup_handler(log, std::move(honest_command_handler));
}

}

module_backend_api_t* ell::setup_handler(dnet_logger *log,
	std::unique_ptr<honest_command_handler> honest_command_handler)
{
	(void) log;

	std::unique_ptr<module_backend_api_t> module_backend_api(new module_backend_api_t);
	module_backend_api->destroy_handler = destroy_module_backend;
	module_backend_api->command_handler = command_handler;
	module_backend_api->iterator = iterator;
	module_backend_api->private_data = honest_command_handler.release();
	return module_backend_api.release();
}

module_backend_api_t* ell::setup_handler(dnet_logger *log,
	std::unique_ptr<uncomplicated_handler> uncomplicated_handler
)
{
	std::function<module_backend_api_t *()> function = std::bind(&setup_handler_throw, log, std::ref(uncomplicated_handler));
	return decorate_exception<module_backend_api_t *>(log, function, NULL);
}
