#ifndef __SRW_H
#define __SRW_H

#ifdef __cplusplus
extern "C" {
#endif

#include <stdio.h>
#include <stdint.h>

struct srwc {
	void		*handler;
	void		*priv;
};

struct srwc *srwc_init_python(char *bin_path, char *log_path, char *pipe_base, char *init_path, int num, void *priv);
void srwc_cleanup_python(struct srwc *s);

struct srwc_ctl {
	char		*cmd;
	void		*binary;

	uint64_t	cmd_size;
	uint64_t	binary_size;

	char		*result;
	uint64_t	res_size;
};

int srwc_process(struct srwc *s, struct srwc_ctl *ctl);
int srwc_drop(struct srwc *s, int pid);

#ifdef __cplusplus
}
#endif

#endif /* __SRW_H */
