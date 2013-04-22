#ifndef FUNCTIONAL_P_H
#define FUNCTIONAL_P_H

#include <functional>

namespace ioremap { namespace elliptics {

// Helper class for functor duties
// It's nothing more than implementation detail
template <typename Pointer, typename Func, typename ReturnType, typename... Args>
struct magic_bind_result
{
    magic_bind_result(const Pointer &pointer, Func func)
        : pointer(pointer), func(func)
    {
    }

    Pointer pointer;
    Func func;

    ReturnType operator() (Args... args)
    {
        return (*pointer.*func)(args...);
    }
};

// Creates std::function-wrapper around object method
// It was created to avoid a lot of std::placeholders::whatever at function binding
template <typename Pointer, typename Object, typename ReturnType, typename... Args>
std::function<ReturnType (Args...)> bind_method(const Pointer &pointer, ReturnType (Object::*func) (Args...))
{
    return magic_bind_result<Pointer, ReturnType (Object::*) (Args...), ReturnType, Args...>(pointer, func);
}

} }

#endif // FUNCTIONAL_P_H
