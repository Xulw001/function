/*
 * Copyright (c) 2021,xulw. All Rights Reserved.
 */
#pragma once

struct list_head{
	struct list_head *next, *prev;
};

#ifndef WIN32
typedef enum
{
	ERROR = -1,
	OK = 0,
	FALSE = 0,
	TRUE = 1,
} boolean;
#endif // !_boolean

#ifndef NULL
#define NULL 0
#endif

#ifndef byte
typedef unsigned char byte;
#endif

#ifndef uint8_t
typedef unsigned char uint8_t;
#endif

#ifndef uint16_t
typedef unsigned short uint16_t;
#endif

#ifndef uint
typedef unsigned int uint;
#endif

#ifndef int64_t
typedef long long int64_t;
#endif

#ifndef uint64_t
typedef unsigned long long uint64_t;
#endif
#ifndef _SIZE_T_DEFINED
#ifdef _WIN64
typedef unsigned long long size_t;
#else
typedef unsigned int size_t;
#endif
#endif
