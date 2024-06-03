#pragma once

#ifdef NTDDI_VERSION	// kernel
  #ifndef _WIN64
    #error Only 64-bit is supported
  #endif
#else                   // user
  #ifdef _WIN64
    #error Only 64-bit is supported
  #endif
#endif
