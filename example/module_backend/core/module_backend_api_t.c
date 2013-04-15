#include <elliptics/module_backend/core/module_backend_api_t.h>
#include "../../backends.h"

void report_module_backend_error(const char *what)
{
	dnet_backend_log(DNET_LOG_ERROR, "module_backend: failed: %s\n", what);
}
