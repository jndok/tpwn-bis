#include "helper.h"

macho_map_t *hp_macho_map(const char *path) {
  macho_map_t *map = (macho_map_t*)malloc(sizeof(struct macho_map));

  int kfd = open(path, O_RDONLY);
  if (!kfd)
    return NULL;

  struct stat st;
  fstat(kfd, &st);
  map->ptr = mmap((void*)0x0, st.st_size, PROT_READ, MAP_SHARED, kfd, 0x0);
  if (!map->ptr)
    return NULL;

  map->size=st.st_size;
  return map;
}

uint64_t hp_find_symbol(macho_map_t *map, const char *sym_name)
{
  enum r_codes {
    ERR_WRONG_MAGIC = 1,
    ERR_SYM_NOT_FOUND
  };

  struct mach_header *header=(struct mach_header*)map->ptr;
  if (header->magic != MH_MAGIC_64)
    return ERR_WRONG_MAGIC;

  uint32_t symoff=0;
  uint32_t stroff=0;
  uint32_t nsyms=0;
  struct load_command *lcmds=((void*)header + sizeof(struct mach_header_64));
  for (uint32_t i = 0; i < header->ncmds; i++) {
    if (lcmds->cmd == LC_SYMTAB) {
      struct symtab_command *sym_cmd=(struct symtab_command*)lcmds;
      symoff=sym_cmd->symoff;
      stroff=sym_cmd->stroff;
      nsyms=sym_cmd->nsyms;
      break;
    }
    lcmds=((void*)lcmds+lcmds->cmdsize);
  }

  void *symtab=((void*)header + symoff);
  void *strtab=((void*)header + stroff);
  struct nlist_64* entry=(struct nlist_64*)symtab;
  for (size_t i = 0; i < nsyms; i++) {
    if (strcmp(sym_name, strtab+entry->n_un.n_strx) == 0) {
      return entry->n_value;
    }
    entry=((void*)entry + sizeof(struct nlist_64));
  }

  return ERR_SYM_NOT_FOUND;
}

uint64_t hp_find_kext_base(const char *bundle_id) {
  return (uint64_t)[((NSNumber*)(((__bridge NSDictionary*)OSKextCopyLoadedKextInfo(NULL, NULL))[[NSString stringWithUTF8String:bundle_id]][@"OSBundleLoadAddress"])) unsignedLongLongValue];
}

kern_return_t hp_msg_send_kernel(char* ool_data, size_t ool_data_sz, mach_port_t* port)
{
  kern_return_t kr;
  oolmsg_t *msg=calloc(sizeof(oolmsg_t)+0x2000,1);

  if(!*port){
    mach_port_allocate(mach_task_self(), MACH_PORT_RIGHT_RECEIVE, port);
    mach_port_insert_right(mach_task_self(), *port, *port, MACH_MSG_TYPE_MAKE_SEND);
  }

  bzero(msg,sizeof(oolmsg_t));

  msg->header.msgh_bits = MACH_MSGH_BITS(MACH_MSG_TYPE_MAKE_SEND, 0);
  msg->header.msgh_bits |= MACH_MSGH_BITS_COMPLEX;
  msg->header.msgh_remote_port = *port;
  msg->header.msgh_local_port = MACH_PORT_NULL;
  msg->header.msgh_size = sizeof(oolmsg_t);
  msg->header.msgh_id = 1;
  msg->body.msgh_descriptor_count = 1;
  msg->desc.address = (void *)ool_data;
  msg->desc.size = ool_data_sz;
  msg->desc.type = MACH_MSG_OOL_DESCRIPTOR;

  kr=mach_msg((mach_msg_header_t *)msg, MACH_SEND_MSG, sizeof(oolmsg_t), 0, 0, 0, 0 );
  free(msg);

  return kr;
}

void *hp_msg_recv_kernel(mach_port_t port)
{
  oolmsg_t *msg=calloc(sizeof(oolmsg_t)+0x2000,1);
  bzero(msg,sizeof(oolmsg_t)+0x2000);
  mach_msg((mach_msg_header_t *)msg, MACH_RCV_MSG, 0, sizeof(oolmsg_t)+0x2000, (port), 0, MACH_PORT_NULL);

  return msg->desc.address;
}
