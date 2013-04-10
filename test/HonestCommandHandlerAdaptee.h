#pragma once

#include "HonestCommandHandler.h"
#include "UncomplicatedHandler.h"
#include <memory>

namespace ioremap {
namespace elliptics {

class HonestCommandHandlerAdaptee : public HonestCommandHandler {
public:
	HonestCommandHandlerAdaptee(std::unique_ptr<UncomplicatedHandler> uncomplicatedHandler);
	virtual int file_write(module_backend_t *r, void *state, dnet_cmd *cmd, void *data);
	virtual int file_read(module_backend_t *r, void *state, dnet_cmd *cmd, void *data);
	virtual int file_info(module_backend_t *r, void *state, dnet_cmd *cmd);
private:
	std::unique_ptr<UncomplicatedHandler> uncomplicatedHandler_;
};

}
}
