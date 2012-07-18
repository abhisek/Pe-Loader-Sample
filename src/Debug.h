#ifndef _DEBUG_H
#define _DEBUG_H

#include <stdio.h>

#define __DEBUG

#ifdef __DEBUG
#include <strsafe.h>
#define _DMSG(x, ...)	do { \
							CHAR __dmsg_str[1024];	\
							StringCbPrintfA(__dmsg_str, sizeof(__dmsg_str), x, __VA_ARGS__);	\
							printf("DMSG: %s\n", __dmsg_str);	\
						} while(0)
#else
#define _DMSG(x)		do { } while(0)
#endif

#endif