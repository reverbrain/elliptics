#include <elliptics/module_backend.hpp>
#include <iostream>

/**
 * This is a example of implementing elliptics backend.
 * To implement elliptics backend as a shared library module,
 * you need to put a symbol with @a module_constructor interface
 * to that library. You can do it by yourself, or there is several
 * helper classes in C++. If you want to develop your module in
 * elliptics hardcode API, you should use derive from
 * @a ioremap::elliptics::honest_command_handler interface.
 * It is proxies elliptics command handler core functions to you,
 * and all you need to do is to reimplement them. If you want to
 * do things fast'n'dirty, you should derive from
 * @a ioremap::elliptics::uncomplicated_handler. This is handler
 * with very simple api, but with lower performance.
 * This is done in this example.
 */

namespace {
using namespace ioremap::elliptics;
/**
 * The simplest way to implement elliptics backend - is to derive from
 * @a uncomplicated_handler and implement it's methods.
 */
class test_uncomplicated_handler : public uncomplicated_handler {
public:
	/**
	 * Here we got elliptics key it want to read, but we faking it.
	 */
	virtual std::string read(const std::string &key)
	{
		std::string result("You want \"" + key + "\"? Am I right?\n");
		return result;
	}
};

/**
 * This is not exception safe module implementation, it can throw.
 */
module_backend_api_t * uncomplicated_handler_constructor_throw(module_backend_config_t *module_backend_config)
{
	std::unique_ptr<uncomplicated_handler> uncomplicated_handler(new test_uncomplicated_handler());
	/// register module_backend_config in module_backend_api_t
	return setup_handler(module_backend_config->log, std::move(uncomplicated_handler));
}

}

/**
 * This function is symbol that elliptics is searching for.
 * It will call it to load this module
 */
extern "C"
module_backend_api_t * uncomplicated_handler_constructor(module_backend_config_t *module_backend_config)
{
	using namespace ioremap::elliptics;
	/// bind function to use it in decorate_exception
	std::function<module_backend_api_t *()> module_constructor=std::bind(uncomplicated_handler_constructor_throw, module_backend_config);
	/// prevent exception leaving C++ code, in C it will crash stack
	return decorate_exception<module_backend_api_t *>(module_backend_config->log, module_constructor, NULL);
}
