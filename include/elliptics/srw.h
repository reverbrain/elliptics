#ifndef __ELLIPTICS_SRW_H
#define __ELLIPTICS_SRW_H

#ifdef __cplusplus
extern "C" {
#endif

#include <elliptics/core.h>

struct sph {
	uint64_t		data_size;		/* size of text data in @data - located after even string */
	uint64_t		binary_size;		/* size of binary data in @data - located after text data */
	uint64_t		flags;
	int			event_size;		/* size of the event string - it is located first in @data */
	int			status;			/* processing status - negative errno code or zero on success */
	int			key;			/* meta-key - used to map header to particular worker, see pool::worker_process() */
	int			num;			/* used in 'new-task' event - common for all handlers -
							 * @num specifies number of workers for new app
							 */
	char			data[0];
} __attribute__ ((packed));

static inline void dnet_convert_sph(struct sph *e)
{
	e->data_size = dnet_bswap64(e->data_size);
	e->binary_size = dnet_bswap64(e->binary_size);
	e->flags = dnet_bswap64(e->flags);
	e->event_size = dnet_bswap32(e->event_size);
	e->status = dnet_bswap32(e->status);
	e->key = dnet_bswap32(e->key);
}

struct srw_init_ctl {
	char			*config;
};

struct dnet_node;
int dnet_srw_update(struct dnet_node *n, int pid);

#ifdef __cplusplus
}
#endif


#endif /* __ELLIPTICS_SRW_H */
