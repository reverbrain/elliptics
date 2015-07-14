#ifndef IOREMAP_ELLIPTICS_REQUEST_FETCHER_HPP
#define IOREMAP_ELLIPTICS_REQUEST_FETCHER_HPP

#include "elliptics.h"
#include "murmurhash.h"

#ifdef __cplusplus
#include <unordered_set>

namespace std
{
	template<>
	struct hash<dnet_id>
	{
		typedef dnet_id argument_type;
		typedef std::size_t result_type;

		result_type operator()(const argument_type &key) const
		{
			return MurmurHash64A(reinterpret_cast<const char *>(&key), sizeof(dnet_id), 0);
		}
	};
}

bool operator == (const dnet_id &lhs, const dnet_id &rhs)
{
	return !dnet_id_cmp(&lhs, &rhs);
}

class dnet_request_fetcher
{
public:
	dnet_request_fetcher(int num_pool_threads);

	dnet_io_req *take_request(dnet_work_io *wio);
	void release_request(const dnet_io_req *req);

private:

private:
	std::unordered_set<dnet_id> m_locked_keys;
};

extern "C" {
#endif // __cplusplus

void *dnet_create_request_fetcher(int num_pool_threads);
void dnet_destroy_request_fetcher(void *fetcher);

struct dnet_io_req *dnet_take_request(struct dnet_work_io *wio);
void dnet_release_request(struct dnet_work_io *wio, const struct dnet_io_req *req);

#ifdef __cplusplus
} // extern "C"
#endif

#endif // IOREMAP_ELLIPTICS_REQUEST_FETCHER_HPP
