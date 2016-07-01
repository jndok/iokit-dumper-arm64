//
//  main.c
//  iokit-dumper-AArch64
//
//  Created by jndok on 30/06/16.
//  Copyright © 2016 jndok. All rights reserved.
//

/*  Thanks to:
 *  - i0n1c     -   for providing DOT source files from his tool (https://github.com/stefanesser/ios-kerneldocs). Was very useful to improve the DOT file generation code and for double checking my algorithm was working correctly.
 *  - jlevin    -   for providing useful tools such as joker, which helped me out a lot with this project.
 *
 */

#include <stdio.h>
#include <getopt.h>

#include "libdump.h"

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

int usage(void)
{
    fprintf(stderr, "usage: ./iokit-dumper-arm64 -f <path_to_kernelcache> -o <output_file>\n");
    return -1;
}

int main(int argc, const char * argv[]) {

    if (argc < 2)
        return usage();
    
    const char *kernelcache_path = NULL;
    const char *output_file = NULL;
    
    int32_t opt = 0;
    while ((opt = getopt(argc, (char * const *)argv, "f:o:")) != -1) {
        switch (opt) {
            case 'f':
                kernelcache_path = optarg;
                break;
            case 'o':
                output_file = optarg;
                break;
            case '?':
                return usage();
        }
    }
    
    if (!kernelcache_path)
        return usage();
    
    fprintf(stdout, "(i) Attempting to load kernelcache at path \'%s\'...\n", kernelcache_path);
    
    macho_map_t *map = map_macho_with_path(kernelcache_path);
    if (!map) {
        printf("(!) Unable to load kernelcache. Please ensure the path you specified is valid.\n");
        return -2;
    }
    
    printf("(+) Successfully mapped kernelcache at \'%s\'! Starting analysis...\n", kernelcache_path);
    
    struct hierarchy_entry_head head = SLIST_HEAD_INITIALIZER(&head);
    
    for (uint32_t *p = (uint32_t *)(map->map_data); p < (uint32_t *)(map->map_data + map->map_size); p++) {
        if (*p == MH_MAGIC_64) {
            struct mach_header_64 *curr_mh = (struct mach_header_64 *)p;
            parse_mod_init_func(map, curr_mh, &head);
        }
    }
    
    if (!output_file) {
        fprintf(stderr, "(!) Warning! Output file not specified. Dumping to \'/tmp/kernelcache.dot\'...\n");
        output_file = "/tmp/kernelcache.dot";
    }
    
    int fd = open(output_file, O_CREAT | O_RDWR, 0666);
    if (fd < 0) {
        fprintf(stderr, "(!) Error: Unable to create output file.\n");
        return -3;
    }
    
    char dot_digraph_string[512] = "digraph { fontsize=120; labelloc=t; rankdir=LR; pagedir=BL; clusterrank=local;\n";
    write(fd, dot_digraph_string, strlen(dot_digraph_string));
    
    struct hierarchy_entry *p = NULL;
    SLIST_FOREACH(p, &head, entries) {
        
        char dot_class_string[256] = {0};
        sprintf(dot_class_string, "%s [fontsize=20; label=\"%s\"; style=filled; color=green; shape=\"box\"];\n", p->class_name, p->class_name);
        
        write(fd, dot_class_string, strlen(dot_class_string));
        
        struct hierarchy_entry *parent = find_parent(&head, p->set.reg_x2);
        if (parent) {
            char dot_parent_string[512] = {0};
            sprintf(dot_parent_string, "%s -> %s\n", p->class_name, parent->class_name);
        
            write(fd, dot_parent_string, strlen(dot_parent_string));
        }
    }
    
    write(fd, "}", sizeof(uint8_t));
    
    fprintf(stdout, "(+) Success! Dumped to %s!\n", output_file);
     
    return 0;
}
