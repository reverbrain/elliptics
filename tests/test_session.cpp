#include "test_session.hpp"
#include "library/elliptics.h"
#include "library/tests.h"

namespace ioremap { namespace elliptics {

test_session::test_session(const session &sess)
: m_session(sess)
{
}

void test_session::toggle_command_send(enum dnet_commands cmd, bool enable_send)
{
	struct dnet_test_settings settings;
	memset(&settings, 0, sizeof(settings));

	dnet_node *n = m_session.get_native_node();
	dnet_node_get_test_settings(n, &settings);
	if (enable_send) {
		settings.commands_mask &= ~(1 << static_cast<unsigned>(cmd));
	} else {
		settings.commands_mask |= 1 << static_cast<unsigned>(cmd);
	}
	dnet_node_set_test_settings(n, &settings);
}

void test_session::toggle_all_command_send(bool enable_send)
{
	struct dnet_test_settings settings;
	memset(&settings, 0, sizeof(settings));

	dnet_node *n = m_session.get_native_node();
	dnet_node_get_test_settings(n, &settings);
	settings.commands_mask = enable_send ? 0 : UINT64_MAX;
	dnet_node_set_test_settings(n, &settings);
}

}} /* namespace ioremap::elliptics */
