#include <stdexcept>

#include <elliptics/session.hpp>

#include <cocaine/framework/dispatch.hpp>
#include <cocaine/framework/logging.hpp>

using namespace ioremap;

class app_context {
public:
    std::string id;
	std::shared_ptr<cocaine::framework::logger_t> log;

    std::unique_ptr<elliptics::file_logger> logger;
    std::unique_ptr<elliptics::node> node;

    elliptics::session reply_client;

	app_context(cocaine::framework::dispatch_t& dispatch);
	void echo(const std::string &cocaine_event, const std::vector<std::string> &chunks, cocaine::framework::response_ptr response);

    elliptics::session create_session(
            const std::vector<std::string> &remotes, const std::vector<int> &groups,
            const std::string &logfile, int loglevel,
            int wait_timeout = 0, int check_timeout = 0
            );
};

app_context::app_context(cocaine::framework::dispatch_t& dispatch)
    : id(dispatch.id())
    , log(dispatch.service_manager()->get_system_logger())
    , reply_client(create_session({"localhost:1025:2"}, {2}, "/dev/stderr", DNET_LOG_ERROR))
{
	COCAINE_LOG_INFO(log, "%s, registering event handler(s)", id.c_str());
	dispatch.on("echo@echo", this, &app_context::echo);

	COCAINE_LOG_INFO(log, "%s, application started", id.c_str());
}

void app_context::echo(const std::string &cocaine_event, const std::vector<std::string> &chunks, cocaine::framework::response_ptr)
{
	elliptics::exec_context context = elliptics::exec_context::from_raw(chunks[0].c_str(), chunks[0].size());

	std::string app;
	std::string event;
	{
		char *p = strchr((char*)cocaine_event.c_str(), '@');
		app.assign(cocaine_event.c_str(), p - cocaine_event.c_str());
		event.assign(p + 1);
	}

	COCAINE_LOG_INFO(log, "event: %s, data-size: %ld", event.c_str(), context.data().size());

    reply_client.reply(context, context.data(), elliptics::exec_context::final);
}

elliptics::session app_context::create_session(
        const std::vector<std::string> &remotes, const std::vector<int> &groups,
        const std::string &logfile, int loglevel,
        int wait_timeout, int check_timeout)
{
    if (remotes.size() == 0) {
        throw std::runtime_error("no remotes have been specified");
    }
    if (groups.size() == 0) {
        throw std::runtime_error("no groups have been specified");
    }

    logger.reset(new elliptics::file_logger(logfile.c_str(), loglevel));
    node.reset(new elliptics::node(*logger));

    if (wait_timeout != 0 || check_timeout != 0) {
        // if unset, use default values as in node.c:dnet_node_create()
        wait_timeout = wait_timeout ? wait_timeout : 5;
        check_timeout = check_timeout ? check_timeout : DNET_DEFAULT_CHECK_TIMEOUT_SEC;
        node->set_timeouts(wait_timeout, check_timeout);
    }

    if (remotes.size() == 1) {
        // any error is fatal if there is a single remote address
        node->add_remote(remotes.front().c_str());

    } else {
        // add_remote throws errors if:
        //  * it can not parse address
        //  * it can not connect to a specified address
        //  * there is address duplication (NOTE: is this still true?)
        // In any case we ignore all errors in hope that at least one would suffice.
        int added = 0;
        for (const auto &i : remotes) {
            try {
                node->add_remote(i.c_str());
                ++added;
            } catch (const elliptics::error &e) {
                char buf[1024];

                snprintf(buf, sizeof(buf), "could not connect to: %s: %s\n",
                        i.c_str(), e.what());

                logger->log(DNET_LOG_ERROR, buf);
            }
        }
        if (added == 0) {
            throw std::runtime_error("no remotes were added successfully");
        }
    }

    elliptics::session session(*node);
    session.set_groups(groups);
    return session;
}

int main(int argc, char **argv)
{
	return cocaine::framework::run<app_context>(argc, argv);
}


