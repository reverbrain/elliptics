#include "elliptics.h"

size_t dnet_backend_info_list_count(dnet_backend_info_list *backends)
{
	return backends ? backends->backends.size() : 0;
}
