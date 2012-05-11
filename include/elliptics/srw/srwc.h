#ifndef __SRW_H
#define __SRW_H

#ifdef __cplusplus
extern "C" {
#endif

#include <stdio.h>
#include <stdint.h>

#include <elliptics/srw/base.h>

struct srwc {
	void		*handler;
	void		*priv;
};

struct srwc *srwc_init(struct srw_init_ctl *ctl);
void srwc_cleanup(struct srwc *s);

struct srwc_ctl {
	struct sph	header;

	char		*result;
	uint64_t	res_size;
};

int srwc_process(struct srwc *s, struct srwc_ctl *ctl, const char *data);
int srwc_drop(struct srwc *s, int pid);

#ifdef __cplusplus
}
#endif

#endif /* __SRW_H */
