#include "ModuleRegistration.h"
#include "CallbackUncomplicatedHandler.h"
#include <iostream>

extern "C"
module_backend_api_t* uncomplicated_handler(module_backend_config_t* module_backend_config)
{
	using namespace ioremap::elliptics;
	std::cout << "Argument: " << module_backend_config->module_argument << std::endl;
	CallbackUncomplicatedHandler::ReadCallback readCallback=[](const std::string& key) {
		std::string result("Get: " +key+" \n");
		std::cout << result << std::endl;
		return result;
	};
	std::unique_ptr<UncomplicatedHandler> uncomplicatedHandler(new CallbackUncomplicatedHandler(readCallback));
	return registerUncomplicatedBackend(std::move(uncomplicatedHandler));
}
