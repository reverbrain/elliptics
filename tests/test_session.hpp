#ifndef TEST_ELLIPTICS_SESSION_HPP
#define TEST_ELLIPTICS_SESSION_HPP

#include <elliptics/cppdef.h>

namespace ioremap { namespace elliptics {

class test_session
{
public:
	test_session(const session &sess);

	/*!
	 * Enables or disables sending command to remote node.
	 * If disabled, then appropriate session operations will be timeouted.
	 */
	void toggle_command_send(enum dnet_commands cmd, bool enable_send);
	/*!
	 * Enables or disables sending any command to remote node.
	 * If disabled, then all session operations will be timeouted.
	 */
	void toggle_all_command_send(bool enable_send);

private:
	const session &m_session;
};

}} /* namespace ioremap::elliptics */

#endif // TEST_ELLIPTICS_SESSION_HPP
