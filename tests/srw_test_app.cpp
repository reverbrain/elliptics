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
};

app_context::app_context(cocaine::framework::dispatch_t& dispatch)
	: id(dispatch.id())
	, log(dispatch.service_manager()->get_system_logger())
{
	COCAINE_LOG_INFO(log, "%s, registering event handler(s)", id.c_str());
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

	const std::string log_path = info.path + "/app.log";

	logger.reset(new elliptics::file_logger(log_path.c_str(), DNET_LOG_DEBUG));
	node.reset(new elliptics::node(*logger));

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
		response->error(-EINVAL, "I'm not inited yet");
		return;
	}

	elliptics::exec_context context = elliptics::exec_context::from_raw(chunks[0].c_str(), chunks[0].size());

	COCAINE_LOG_INFO(log, "event: %s, data-size: %ld", event.c_str(), context.data().size());

	elliptics::async_reply_result result = reply_client->reply(context, context.data(), elliptics::exec_context::final);
	result.connect(std::bind(noop_function, response));
}

int main(int argc, char **argv)
{
	return cocaine::framework::run<app_context>(argc, argv);
}


