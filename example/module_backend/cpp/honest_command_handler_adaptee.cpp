#include "honest_command_handler_adaptee.hpp"
#include "../core/module_backend_t.h"
#include <elliptics/interface.h>
#include <iostream>

using namespace ioremap::elliptics;

namespace {
std::string dnet_cmd2string(const dnet_id& id)
{
	std::string result(reinterpret_cast<const char*>(id.id), DNET_ID_SIZE);
	std::string::size_type position = result.find('\0');
	if (position != std::string::npos) {
		result.resize(position);
	}
	return result;
}
}

honest_command_handler_adaptee::honest_command_handler_adaptee(std::unique_ptr<uncomplicated_handler> uncomplicated_handler)
: m_uncomplicated_handler(std::move(uncomplicated_handler))
{
}

int honest_command_handler_adaptee::file_write(module_backend_t */*r*/, void *state, dnet_cmd *cmd, void */*data*/)
{
	return dnet_send_file_info_without_fd(state, cmd, 0, -1);
}

int honest_command_handler_adaptee::file_read(module_backend_t */*r*/, void *state, dnet_cmd *cmd, void *data)
{
	const std::string key(dnet_cmd2string(cmd->id));
	const std::string result = m_uncomplicated_handler->read(key);
	dnet_io_attr *io = static_cast<dnet_io_attr *>(data);
	io->size = result.size();
	return dnet_send_read_data(state, cmd, io, (void *)result.data(), -1, io->offset, 0);
}

int honest_command_handler_adaptee::file_info(module_backend_t */*r*/, void *state, dnet_cmd *cmd)
{
	return dnet_send_file_info_without_fd(state, cmd, 0, -1);
}
