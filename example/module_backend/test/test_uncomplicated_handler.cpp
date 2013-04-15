#include <elliptics/module_backend/cpp/registration.hpp>
#include <iostream>

namespace {
using namespace ioremap::elliptics;
/**
 * The simplest way to implement elliptics backend - is to derive from
 * @a uncomplicated_handler and implement it's methods.
 */
class test_uncomplicated_handler : public uncomplicated_handler {
public:
	/**
	 * Here we got elliptics key it want to read
	 */
	virtual std::string read(const std::string &key)
	{
		std::string result("You want \"" + key + "\"? Am I right?\n");
		return result;
	}
};

module_backend_api_t * uncomplicated_handler_constructor_throw(module_backend_config_t */*module_backend_config*/)
{
	std::unique_ptr<uncomplicated_handler> uncomplicated_handler(new test_uncomplicated_handler());
	/// register module_backend_config in module_backend_api_t
	return setup_handler(std::move(uncomplicated_handler));
}

}

/**
 * This function is symbol that elliptics search for.
 * It will call it to load this module
 */
extern "C"
module_backend_api_t * uncomplicated_handler_constructor(module_backend_config_t *module_backend_config)
{
	using namespace ioremap::elliptics;
	/// bind function to use it in decorate_exception
	std::function<module_backend_api_t *()> module_constructor=std::bind(uncomplicated_handler_constructor_throw, module_backend_config);
	/// prevent exception leaving C++ code, in C it will crash stack
	return decorate_exception<module_backend_api_t *>(module_constructor, NULL);
}
