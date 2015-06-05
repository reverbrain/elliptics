#ifndef __DNET_TESTS_H
#define __DNET_TESTS_H

#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

struct dnet_node;

struct dnet_test_settings
{
	/*
	 * If i'th bit is set, then commands with value 'i' are not sended.
	 * See enum dnet_commands, where DNET_CMD_LOOKUP command has value '1'
	 */
	uint64_t	commands_mask;
};

void dnet_node_set_test_settings(struct dnet_node *n, struct dnet_test_settings *settings);
int dnet_node_get_test_settings(struct dnet_node *n, struct dnet_test_settings *settings);

#ifdef __cplusplus
}
#endif

#endif /* __DNET_TESTS_H */
