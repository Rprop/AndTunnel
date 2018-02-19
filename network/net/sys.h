#pragma once
#include <stdint.h>
#ifdef _WINDOWS
# define LITTLE_ENDIAN    1234
# define BYTE_ORDER       LITTLE_ENDIAN
#else
# include <endian.h>
# define _byteswap_uint64 __swap64
# define _byteswap_ulong  __swap32
# define _byteswap_ushort __swap16
# define _In_
#endif // _WINDOWS