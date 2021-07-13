#ifndef _XC_DEV_H
#define _XC_DEV_H

#include <bits/stdint-uintn.h>
#include <stdint.h>

// @see https://github.com/iovisor/bcc/blob/master/src/cc/export/helpers.h
#include "include/helpers.h"

#define size_t u32

#define u64 __u64
#define u32 __u32
#define u8  __u8

#define _PID_ 0
#define _DEV_

#endif
