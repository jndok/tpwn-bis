//
//  ropnroll.c
//  ropnroll_final
//
//  Created by jndok on 14/11/15.
//  Copyright © 2015 jndok. All rights reserved.
//

#include "ropnroll.h"

uint64_t flags=0;

struct segment_command_64 *find_segment_in_map(mapping_t *map, const char *segname)
{
    struct mach_header_64 *header = (struct mach_header_64*)map->map;
    if (header->magic != MH_MAGIC_64)
        return NULL;
    
    struct load_command *lcmd = ((void*)header + sizeof(struct mach_header_64));
    for (uint32_t i=0; i<header->ncmds; ++i) {
        if (lcmd->cmd==LC_SEGMENT_64) {
            struct segment_command_64 *seg=(struct segment_command_64*)lcmd;
            if (strcmp(seg->segname, segname) == 0) {
                return seg;
            }
        }
        
        lcmd = ((void*)lcmd + lcmd->cmdsize);
    }
    
    return NULL;
}

uint32_t calculate_gadget_size(gadget_t gadget)
{
    char *byte = (char*)gadget;
    uint32_t sz;
    
    for (sz=0; *(uint8_t*)(byte+sz) != 0xc3; ++sz);
    
    return sz+1;
}

uint64_t locate_gadget_in_map(mapping_t *map, gadget_t gadget, gadget_size_t sz)
{
    if (!map->map)
        return 0;
    
    void *loc = memmem(map->map, map->map_size, gadget, sz);
    if (!loc)
        return 0;
    
    uint64_t ret=loc-map->map;
    
    return ret;
}

uint64_t locate_symbol_in_map(mapping_t *map, const char *sym_name)
{
    void *symtable=NULL, *strtable=NULL;
    uint32_t nsyms=0;
    struct mach_header_64 *header = (struct mach_header_64*)map->map;
    if (header->magic != MH_MAGIC_64)
        return 0;
    
    struct load_command *lcmd = ((void*)header + sizeof(struct mach_header_64));
    for (uint32_t i=0; i<header->ncmds; ++i) {
        if (lcmd->cmd==LC_SYMTAB) {
            struct symtab_command *sym_cmd=(struct symtab_command*)lcmd;
            symtable=((void*)header + sym_cmd->symoff);
            strtable=((void*)header + sym_cmd->stroff);
            nsyms=sym_cmd->nsyms;
            
            break;
        }
        
        lcmd = ((void*)lcmd + lcmd->cmdsize);
    }

    struct nlist_64 *entry=(struct nlist_64*)symtable;
    for (uint32_t i=0; i<nsyms; ++i) {
        if (strcmp(strtable+(entry->n_un.n_strx), sym_name) == 0) {
            //printf("---> %#llx\n", entry->n_value);
            return entry->n_value;
        }
        entry=((void*)entry + sizeof(struct nlist_64));
    }
    
    return 0;
}

uint64_t locate_kernel_text(mapping_t *map)
{
    struct segment_command_64 *kernel_text=find_segment_in_map(map, SEG_TEXT);
    return kernel_text->vmaddr;
}

uint64_t kext_base_address(const char *bundle_id)
{
    return KextUnslidBaseAddress(bundle_id);
}

uint64_t get_kslide(void)
{
    if (getuid() != 0)
        return KSLIDE_UNKNOWN;
    
    uint64_t kslide=0;
    uint64_t kslide_sz=sizeof(kslide);
    
    syscall(SYS_kas_info, KAS_INFO_KERNEL_TEXT_SLIDE_SELECTOR, &kslide, &kslide_sz);
    
    return kslide;
}

uint64_t slide_kernel_pointer(uint64_t pointer, uint64_t kslide)
{
    if (kslide==KSLIDE_UNKNOWN) {
        return pointer;
    } else {
        return pointer+kslide;
    }
    
    return 0;
}
