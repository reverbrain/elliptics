#ifndef __DNET_TRANS_H
#define __DNET_TRANS_H

/*
 * Each read transaction reply is being split into
 * chunks of this bytes max, thus reading transaction
 * callback will be invoked multiple times.
 */
#define DNET_MAX_READ_TRANS_SIZE	(1024*1024*10)

#endif /* __DNET_TRANS_H */
