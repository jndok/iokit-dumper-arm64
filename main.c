//
//  main.c
//  iokit-dumper-AArch64
//
//  Created by jndok on 30/06/16.
//  Copyright © 2016 jndok. All rights reserved.
//

#include <stdio.h>

#include "libdump.h"

#define PATH "/Users/jndok/Desktop/dumps/kernel/kerndump.i6.921b1.macho"

void parse_mod_init_func(struct macho_map *map, struct mach_header_64 *mh, struct hierarchy_entry_head *head)
{
    struct segment_command_64 *seg_data = find_segment_command64(mh, SEG_DATA);
    if (!seg_data)
        return;
    
    struct section_64 *sect_mod_init_func = find_section64(seg_data, "__mod_init_func");
    if (!sect_mod_init_func)
        return;
    
    uint64_t mod_init_func_off = sect_mod_init_func->offset;
    uint64_t mod_init_func_size = sect_mod_init_func->size;
    
    dmp_ctx_t *ctx = init_dump_ctx(map);
    set_ctx_image(ctx, mh);
    
    for (uint64_t *p = (uint64_t *)((void *)mh + mod_init_func_off); p < (uint64_t *)((void *)mh + mod_init_func_off + mod_init_func_size); p++) {
        emulate_constructor(ctx, *p, head);
    }
    
}

int main(int argc, const char * argv[]) {

    macho_map_t *map = map_macho_with_path(PATH);
    if (!map) {
        printf("(!) Unable to map.\n");
        return -1;
    }
    
    printf("(+) Mapped successfully!\n");
    
    struct hierarchy_entry_head head = SLIST_HEAD_INITIALIZER(&head);
    
    for (uint32_t *p = (uint32_t *)(map->map_data); p < (uint32_t *)(map->map_data + map->map_size); p++) {
        if (*p == MH_MAGIC_64) {
            struct mach_header_64 *curr_mh = (struct mach_header_64 *)p;
            parse_mod_init_func(map, curr_mh, &head);
        }
    }
    
    rebuild_hierarchy(&head);
     
    return 0;
}
