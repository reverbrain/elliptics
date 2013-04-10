#pragma once

#include "UncomplicatedHandler.h"
#include "HonestCommandHandler.h"
#include "../example/module_backend/module_backend_t.h"
#include <memory>

namespace ioremap {
namespace elliptics {

module_backend_api_t* registerHonestCommandHandler(
	std::unique_ptr<HonestCommandHandler> honestCommandHandler
);

module_backend_api_t* registerUncomplicatedBackend(
	std::unique_ptr<UncomplicatedHandler> uncomplicatedHandler
);

static const char* UNKNOWN_EXPLANATION;

template <typename T>
T reportException(const char* what, const T& errorValue)
{
	dnet_backend_log(DNET_LOG_ERROR, "Fail to create module_backend: %s\n", what);
	return errorValue;
}

/// @todo FIXME rename to decorator (decorator::exception)
template<typename T>
T exception_filter(std::function<T()> function, const T& errorValue)
{
	try {
		return function();
	} catch (std::exception& e) {
		return reportException<T>(e.what(), errorValue);
	} catch (...) {
		return reportException<T>(UNKNOWN_EXPLANATION, errorValue);
	}
}

}
}
