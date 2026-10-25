#ifndef SEFS_API_H
#define SEFS_API_H

/* A Windows DLL exports nothing by default; SEFS_EXPORTS is set in CMakeLists.txt. */
#ifdef _WIN32
#  ifdef SEFS_EXPORTS
#    define SEFS_API __declspec(dllexport)
#  else
#    define SEFS_API __declspec(dllimport)
#  endif
#else
#  define SEFS_API
#endif

#endif
