#include "tests.h"
#include "elliptics.h"

void dnet_node_set_test_settings(struct dnet_node *n, struct dnet_test_settings *settings)
{
	pthread_rwlock_wrlock(&n->test_settings_lock);
	if (!n->test_settings) {
		n->test_settings = malloc(sizeof(struct dnet_test_settings));
	}
	memcpy(n->test_settings, settings, sizeof(struct dnet_test_settings));
	pthread_rwlock_unlock(&n->test_settings_lock);
}

int dnet_node_get_test_settings(struct dnet_node *n, struct dnet_test_settings *settings)
{
	int err = -ENOENT;
	pthread_rwlock_rdlock(&n->test_settings_lock);
	if (n->test_settings) {
		memcpy(settings, n->test_settings, sizeof(struct dnet_test_settings));
		err = 0;
	}
	pthread_rwlock_unlock(&n->test_settings_lock);
	return err;
}
