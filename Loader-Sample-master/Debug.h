#ifndef _DEBUG_H
#define _DEBUG_H

#include <stdio.h>

#define __DEBUG

#ifdef __DEBUG
#include <strsafe.h>
#define DMSG(x, ...)	fprintf(stderr, "[+] " x "\n", __VA_ARGS__)
#define EMSG(x, ...)	fprintf(stderr, "[-] " x "\n", __VA_ARGS__)
#else
#define DMSG(x, ...)	do { } while(0)
#define EMSG(x, ...)	do { } while(0)
#endif

#endif
