#include <stdexcept>

#include <elliptics/session.hpp>

#include <cocaine/framework/dispatch.hpp>
#include <cocaine/framework/logging.hpp>

#define NO_UPPLOAD_APPLICATION
#include "srw_test.hpp"

using namespace ioremap;

class app_context {
public:
	std::string id;
	std::shared_ptr<cocaine::framework::logger_t> log;

	std::unique_ptr<elliptics::file_logger> logger;
	std::unique_ptr<elliptics::node> node;
	std::unique_ptr<elliptics::session> reply_client;

	app_context(cocaine::framework::dispatch_t& dispatch);

	void init(const std::string &cocaine_event, const std::vector<std::string> &chunks, cocaine::framework::response_ptr response);
	void echo(const std::string &cocaine_event, const std::vector<std::string> &chunks, cocaine::framework::response_ptr response);
	void noreply(const std::string &cocaine_event, const std::vector<std::string> &chunks, cocaine::framework::response_ptr response);
};

app_context::app_context(cocaine::framework::dispatch_t& dispatch)
	: id(dispatch.id())
	, log(dispatch.service_manager()->get_system_logger())
{
	COCAINE_LOG_INFO(log, "%s, registering event handler(s)", id.c_str());

	dispatch.on("noreply", this, &app_context::noreply);
	dispatch.on("echo", this, &app_context::echo);
	dispatch.on("init", this, &app_context::init);

	COCAINE_LOG_INFO(log, "%s, application started", id.c_str());
}

static void noop_function(cocaine::framework::response_ptr)
{
}

void app_context::init(const std::string &, const std::vector<std::string> &chunks, cocaine::framework::response_ptr response)
{
	elliptics::exec_context context = elliptics::exec_context::from_raw(chunks[0].c_str(), chunks[0].size());

	tests::node_info info;
	info.unpack(context.data().to_string());

	const std::string log_path = info.path + "/" + id + ".log";

	logger.reset(new elliptics::file_logger(log_path.c_str(), DNET_LOG_DEBUG));
	node.reset(new elliptics::node(elliptics::logger(*logger, blackhole::log::attributes_t())));

	for (auto it = info.remotes.begin(); it != info.remotes.end(); ++it) {
		node->add_remote(it->c_str());
	}

	reply_client.reset(new elliptics::session(*node));
	reply_client->set_groups(info.groups);

	elliptics::async_reply_result result = reply_client->reply(context, std::string("inited"), elliptics::exec_context::final);
	result.connect(std::bind(noop_function, response));
}

void app_context::echo(const std::string &event, const std::vector<std::string> &chunks, cocaine::framework::response_ptr response)
{
	if (!reply_client) {
		response->error(-EINVAL, "I'm not initialized yet");
		return;
	}

	elliptics::exec_context context = elliptics::exec_context::from_raw(chunks[0].c_str(), chunks[0].size());

	COCAINE_LOG_INFO(log, "echo: event: %s, data-size: %ld", event.c_str(), context.data().size());

	elliptics::async_reply_result result = reply_client->reply(context, context.data(), elliptics::exec_context::final);
	result.connect(std::bind(noop_function, response));
}

/**
 * @noreply function is used for timeout tests - it doesn't send reply and it must not return (at least for the timeout duration),
 * since cocaine sends 'close' event back to server-side elliptics which in turn sends completion event to client-side elliptics.
 * That completion prevents transaction from timing out, which breaks the test.
 *
 * Be careful, this function doesn't check whether application was initialized or not (compare to @echo function).
 * It is possible that new cocaine workers will be spawned only to handle this event type, and client will not send 'init' event to them.
 */
void app_context::noreply(const std::string &event, const std::vector<std::string> &chunks, cocaine::framework::response_ptr response)
{
	(void) response;

	elliptics::exec_context context = elliptics::exec_context::from_raw(chunks[0].c_str(), chunks[0].size());

	COCAINE_LOG_INFO(log, "noreply: event: %s, data-size: %ld", event.c_str(), context.data().size());

	sleep(30);
}

int main(int argc, char **argv)
{
	return cocaine::framework::run<app_context>(argc, argv);
}


