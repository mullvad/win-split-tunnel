#pragma once

#ifdef NTDDI_VERSION	// kernel
  #ifndef _AMD64_
    #error The only supported compilation target is x64
  #endif
#else                   // user
  #ifdef WIN32
    #error The only supported compilation target is x64
  #endif
#endif
