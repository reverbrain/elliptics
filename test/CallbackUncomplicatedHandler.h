#pragma once

#include "UncomplicatedHandler.h"
#include <functional>

namespace ioremap {
namespace elliptics {

class CallbackUncomplicatedHandler : public UncomplicatedHandler {
public:
	typedef std::function<std::string(const std::string&)> ReadCallback;
public:
	CallbackUncomplicatedHandler(ReadCallback readCallback);
	virtual std::string read(const std::string& key);
private:
	ReadCallback readCallback_;
};

}
}
