#ifndef __MEASURE_POINTS_H
#define __MEASURE_POINTS_H

#ifdef HAVE_HANDYSTATS
    #ifdef __cplusplus
        #include <handystats/measuring_points.hpp>
    #else
        #include <handystats/measuring_points.h>
    #endif

    #define __HANDY_NAME_USE BOOST_PP_CAT(__C_HANDY_NAME_BUF_, __LINE__)
    #define __HANDY_NAME_SET(...) char __HANDY_NAME_USE[255]; snprintf(__HANDY_NAME_USE, (sizeof(__HANDY_NAME_USE) - 1), __VA_ARGS__)
    #define FORMATTED(MACRO, NAME_ARGS, ...) __HANDY_NAME_SET NAME_ARGS; MACRO(__HANDY_NAME_USE, ##__VA_ARGS__)
#else
    #include "monitor/handystats/stubs.h"
#endif

#endif /* __MEASURE_POINTS_H */
