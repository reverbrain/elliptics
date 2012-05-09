#ifndef __ELLIPTICS_SRW_BASE_HPP
#define __ELLIPTICS_SRW_BASE_HPP

enum srw_types {
	SRW_TYPE_PYTHON	= 0,
	SRW_TYPE_SHARED,
	__SRW_TYPE_MAX
};

struct sph {
	uint64_t		size, binary_size;
	uint64_t		flags;
	int			pad;
	int			status;
	char			data[0];
} __attribute__ ((packed));

struct srw_init_ctl {
	char			*binary; /* path to srw_worker binary - it is used to spawn script workers */
	char			*log; /* srw log path - initialized to the same config string as for 'log' by default */
	char			*pipe; /* pipe base - elliptics will talk to workers via @pipe.c2w and @pipe.w2c */
	char			*init; /* path to initialization object */
	char			*config; /* path to config object */
	void			*priv; /* opaque private data */
	int			type; /* srw worker type */
	int			num; /* number of workers */
} __attribute__ ((packed));

#endif
