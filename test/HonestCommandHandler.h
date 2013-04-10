#pragma once

#include <elliptics/packet.h>
#include "../example/module_backend/module_backend_t.h"

namespace ioremap {
namespace elliptics {

class HonestCommandHandler {
public:
	virtual int file_write(module_backend_t *r, void *state, dnet_cmd *cmd, void *data)=0;
	virtual int file_read(module_backend_t *r, void *state, dnet_cmd *cmd, void *data)=0;
	virtual int file_info(module_backend_t *r, void *state, dnet_cmd *cmd)=0;
	virtual ~HonestCommandHandler();
};

}
}
