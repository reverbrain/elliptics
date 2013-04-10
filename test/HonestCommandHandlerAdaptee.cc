#include "HonestCommandHandlerAdaptee.h"
#include "../example/module_backend/module_backend_t.h"
#include <iostream>

using namespace ioremap::elliptics;

namespace {
std::string dnet_cmd2string(const dnet_id& id)
{
	std::string result(reinterpret_cast<const char*>(id.id), DNET_ID_SIZE);
	std::string::size_type position=result.find('\0');
	if (std::string::npos!=position) {
		result.resize(position);
	}
	return result;
}
}

HonestCommandHandlerAdaptee::HonestCommandHandlerAdaptee(std::unique_ptr<UncomplicatedHandler> uncomplicatedHandler)
: uncomplicatedHandler_(std::move(uncomplicatedHandler))
{
}

int HonestCommandHandlerAdaptee::file_write(module_backend_t */*r*/, void *state, dnet_cmd *cmd, void */*data*/)
{
	return dnet_send_file_info_without_fd(state, cmd, 0, -1);
}

int HonestCommandHandlerAdaptee::file_read(module_backend_t */*r*/, void *state, dnet_cmd *cmd, void *data)
{
	const std::string key(dnet_cmd2string(cmd->id));
	const std::string result=uncomplicatedHandler_->read(key);
	dnet_io_attr *io = static_cast<dnet_io_attr *>(data);
	io->size=result.size();
	return dnet_send_read_data(state, cmd, io, (void*)result.data(), -1, io->offset, 0);
}

int HonestCommandHandlerAdaptee::file_info(module_backend_t */*r*/, void *state, dnet_cmd *cmd)
{
	return dnet_send_file_info_without_fd(state, cmd, 0, -1);
}
