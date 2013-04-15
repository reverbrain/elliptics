#pragma once
#include <string>

namespace ioremap {
namespace elliptics {

/**
 * This is abstract class for simple (aka uncomplicated) interface
 * of elliptics module. This class must be used if you don't interested
 * in internal elliptics structres, and just want to make it work fast.
 */
class uncomplicated_handler {
public:
    /**
     * This function should implement reading data by key
     */
	virtual std::string read(const std::string &key)=0;
	virtual ~uncomplicated_handler();
};

}
}
