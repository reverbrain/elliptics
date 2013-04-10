#include "CallbackUncomplicatedHandler.h"

using namespace ioremap::elliptics;

CallbackUncomplicatedHandler::CallbackUncomplicatedHandler(ReadCallback readCallback)
 : readCallback_(readCallback)
{
}

std::string CallbackUncomplicatedHandler::read(const std::string& key)
{
	return readCallback_(key);
}
