//
//  parser.h
//  iokit-dumper-AArch64
//
//  Created by jndok on 30/06/16.
//  Copyright © 2016 jndok. All rights reserved.
//

#ifndef parser_h
#define parser_h

#include <stdio.h>

#include <machoman/machoman.h>

#define MAP_ADDR_SLIDE(mh, addr)            ((uint64_t)addr + (uint64_t)mh)
#define MAP_ADDR_UNSLIDE(mh, addr)          ((uint64_t)addr - (uint64_t)mh)

#define KERNEL_ADDR_SLIDE(kbase, addr)      ((uint64_t)addr + (uint64_t)kbase)
#define KERNEL_ADDR_UNSLIDE(kbase, addr)    ((uint64_t)addr - (uint64_t)kbase)

#define MAP_ADDR_TO_KERNEL(mh, kbase, addr) (KERNEL_ADDR_SLIDE(kbase, MAP_ADDR_UNSLIDE(mh, addr)))
#define KERNEL_ADDR_TO_MAP(mh, kbase, addr) (MAP_ADDR_SLIDE(mh, KERNEL_ADDR_UNSLIDE(kbase, addr)))

#define INSN_RET                    0xD65F03C0
#define INSN_NOP                    0xD503201F
#define INSN_PROLOG_END             0xA8C17BFD

char *read_line(FILE *fin);

int aarch64_decode_adr (uint32_t insn, int *is_adrp, unsigned *rd, int32_t *offset);
int aarch64_decode_ldr_literal (uint32_t insn, int *is_w, int *is64, unsigned *rt, int32_t *offset);
int aarch64_decode_ldr_immediate(uint32_t insn, uint32_t *offset);
int aarch64_decode_add (uint32_t insn, uint32_t *offset);
int aarch64_decode_b(uint32_t insn, int *is_bl, int32_t *offset);

uint32_t get_constructor_size(struct mach_header_64 *mh, uint64_t constructor_kaddr, uint64_t kbase);

const char *get_kext_name(macho_map_t *map, struct mach_header_64 *mh);

uint64_t find_kimage_base(struct mach_header_64 *mh);
uint64_t find_kimage_os_metaclass_constructor(struct mach_header_64 *mh, uint64_t kimage_base);

#endif /* parser_h */
