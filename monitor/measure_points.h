#ifndef __MEASURE_POINTS_H
#define __MEASURE_POINTS_H

#ifdef HAVE_HANDYSTATS
    #ifdef __cplusplus
        #include <handystats/measuring_points.hpp>
    #else
        #include <handystats/measuring_points.h>
    #endif
#else
    #include "monitor/handystats/stubs.h"
#endif

#endif /* __MEASURE_POINTS_H */
