#include <mach/mach_vm.h>
#include <IOKit/IOKitLib.h>

#import <Foundation/Foundation.h>

#define IOHDIX "IOHDIXController"
#define IOAUDIO "IOAudioEngine"

#define LAND_AREA 0x800
#define MAX_ALLOCS 5

typedef struct kern_obj {
  mach_port_t           kport;
  io_connect_t          kconn;
  uint64_t              kptr;
} kern_obj_t;

uint16_t pwn_init(void);

uint64_t io_audio_engine_infoleak(io_connect_t *conn);
uint16_t or_primitive(uint64_t where);
