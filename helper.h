/*
  helper lib
*/

#define K_PATH "/System/Library/Kernels/kernel"
#define A_PATH "/System/Library/Extensions/IOAudioFamily.kext/Contents/MacOS/IOAudioFamily"

#import <Foundation/Foundation.h>

#include <string.h>
#include <mach/mach.h>
#include <mach-o/loader.h>
#include <mach-o/nlist.h>
#include <sys/mman.h>
#include <sys/stat.h>

typedef void* macho_map_pointer_t;
typedef vm_size_t macho_size_t;

typedef struct {
    mach_msg_header_t header;
    mach_msg_body_t body;
    mach_msg_ool_descriptor_t desc;
    mach_msg_trailer_t trailer;
} oolmsg_t;

typedef struct macho_map {
  macho_map_pointer_t *ptr;
  macho_size_t size;
} macho_map_t;

extern CFDictionaryRef OSKextCopyLoadedKextInfo(CFArrayRef, CFArrayRef);

macho_map_t *hp_macho_map(const char *path);
uint64_t hp_find_symbol(macho_map_t *map, const char *sym_name);
uint64_t hp_find_kext_base(const char *bundle_id);

kern_return_t hp_msg_send_kernel(char* ool_data, size_t ool_data_sz, mach_port_t* port);
void *hp_msg_recv_kernel(mach_port_t port);
