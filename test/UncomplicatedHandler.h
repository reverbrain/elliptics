#pragma once

#include <string>

namespace ioremap {
namespace elliptics {

class UncomplicatedHandler {
public:
	virtual std::string read(const std::string& key)=0;
	virtual ~UncomplicatedHandler();
};

}
}
