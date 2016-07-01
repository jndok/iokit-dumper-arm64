/*
 *      == libmachoman v0.1.0 ==
 *
 *  A simple library providing all you need
 *  for generic Mach-O parsing.
 *  I found myself rewriting this fucking code
 *  in every project, so I finally decided to
 *  do it right, once and for all!
 *
 */

//
//  machoman.h
//  machoman
//
//  Created by jndok on 26/05/16.
//  Copyright © 2016 jndok. All rights reserved.
//

#ifndef machoman_h
#define machoman_h

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/stat.h>
#include <sys/mman.h>
#include <fcntl.h>

#include <mach-o/loader.h>
#include <mach-o/nlist.h>

#define MACHO_MAP_MAGIC 0xDEADC0DE

#define MACHO_MAP_SLIDE_OFFSET(map, off)    ((uint64_t)(map->map_data) + (uint64_t)off)
#define MACHO_MAP_UNSLIDE_OFFSET(map, off)  ((uint64_t)off > (uint64_t)(map->map_data)) ? ((uint64_t)off - (uint64_t)(map->map_data)) : ((uint64_t)off)

enum {
    MMRC_ErrGen = 1
};

typedef struct macho_map {
    uint32_t        map_magic;
    void            *map_data;
    mach_vm_size_t   map_size;
    uint32_t        unique_id;
} macho_map_t;

macho_map_t *map_macho_with_path(const char *path);
void free_macho_map(macho_map_t *map);

__attribute__((always_inline)) boolean_t is_valid_macho_file(const char *path);    /* before you map */
__attribute__((always_inline)) boolean_t is_valid_macho_map(macho_map_t *map);

__attribute__((always_inline)) struct mach_header_64 *get_mach_header_64(macho_map_t *map);

__attribute__((always_inline)) struct load_command **find_all_load_commands(struct mach_header_64 *mh);

__attribute__((always_inline)) struct load_command *find_load_command(struct mach_header_64 *mh, uint32_t lc);
__attribute__((always_inline)) struct segment_command_64 *find_segment_command64(struct mach_header_64 *mh, const char *segname);
__attribute__((always_inline)) struct section_64 *find_section64(struct segment_command_64 *seg64, const char *sectname);

__attribute__((always_inline)) struct symtab_command *find_symtab_command(struct mach_header_64 *mh);
__attribute__((always_inline)) struct dysymtab_command *find_dysymtab_command(struct mach_header_64 *mh);

#endif /* machoman_h */
