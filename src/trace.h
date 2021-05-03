#pragma once

//
// Define GUID and tracing flags.
//

#define WPP_CONTROL_GUIDS                                              \
    WPP_DEFINE_CONTROL_GUID(                                           \
        StTraceGuid, (33E4119D,8A89,4FEC,A90C,C003310B17E9),           \
        WPP_DEFINE_BIT(TRACE_GENERAL)                                  \
        WPP_DEFINE_BIT(TRACE_DRIVER)                                   \
        WPP_DEFINE_BIT(TRACE_DEVICE)                                   \
        )                             

#define WPP_FLAG_LEVEL_LOGGER(flag, level)                             \
    WPP_LEVEL_LOGGER(flag)

#define WPP_FLAG_LEVEL_ENABLED(flag, level)                            \
    (WPP_LEVEL_ENABLED(flag) &&                                        \
        WPP_CONTROL(WPP_BIT_ ## flag).Level >= level)

#define WPP_LEVEL_FLAGS_LOGGER(lvl,flags) \
    WPP_LEVEL_LOGGER(flags)

#define WPP_LEVEL_FLAGS_ENABLED(lvl, flags) \
    (WPP_LEVEL_ENABLED(flags) && WPP_CONTROL(WPP_BIT_ ## flags).Level >= lvl)

//
// This comment block is scanned by the trace preprocessor to define the
// TraceEvents function.
//
// begin_wpp config
// FUNC TraceEvents(LEVEL, FLAGS, MSG, ...);
// end_wpp
//
