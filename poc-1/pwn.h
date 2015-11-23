
//
//  pwn.h
//  poc-1
//
//  Created by jndok on 15/11/15.
//  Copyright © 2015 jndok. All rights reserved.
//

#ifndef pwn_h
#define pwn_h

#include <mach/mach.h>
#include <mach/mach_vm.h>
#import <IOKit/IOKitLib.h>

uint16_t alloc_null(vm_size_t size);

uint64_t io_audio_engine_infoleak(io_connect_t *conn);
uint16_t or_primitive(uint64_t address);

#endif /* pwn_h */
