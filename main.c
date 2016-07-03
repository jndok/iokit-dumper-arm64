//
//  main.c
//  iokit-dumper-AArch64
//
//  Created by jndok on 30/06/16.
//  Copyright © 2016 jndok. All rights reserved.
//

/*  Thanks to:
 *  - i0n1c  (https://twitter.com/i0n1c)            -   for providing DOT source files from his tool (https://github.com/stefanesser/ios-kerneldocs). Was very useful to improve the DOT file generation code and for double checking my algorithm was working correctly.
 *  - jlevin (https://twitter.com/Morpheus______)   -   for providing useful tools such as joker, which helped me out a lot with this project.
 *
 *  ***
 *
 +  Please note that this whole project is WIP. The code is quite ugly.
 *  Fixes and improvements are coming soon.
 +  Feel free to submit a pull request/issue/whatever to contribute to the
 *  project.
 */

#define DOT_DIGRAPH_DECLARATION_BEGIN   "digraph { fontsize=120; labelloc=t; rankdir=LR; pagedir=BL; clusterrank=local;"
#define DOT_DIGRAPH_DECLARATION_END     "}"

#define DOT_CLASS_DECLARATION           "%s [fontsize=20; label=\"%s\"; style=filled; color=yellow; shape=\"box\"];"

#define DOT_HIERARCHY_DECLARTION        "%s -> %s"

#include <stdio.h>
#include <getopt.h>

#include "libdump/libdump.h"

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
    const char *output_path = NULL;

    const char *image_name = NULL;

    boolean_t auto_convert = false;

    int32_t opt = 0;
    while ((opt = getopt(argc, (char * const *)argv, "f:o:n:c")) != -1) {
        switch (opt) {
            case 'f':
                kernelcache_path = optarg;
                break;
            case 'o':
                output_path = optarg;
                break;
            case 'n':
                image_name = optarg;
                break;
            case 'c':   //auto-convert
                auto_convert = true;
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

    if (!output_path) {
        fprintf(stderr, "(!) Warning! Output path not specified. Dumping to \'/tmp/\'...\n");
        output_path = "/tmp/";
    }

    char output_file[512] = {0};
    strcpy(output_file, output_path);
    strcat(output_file, ((image_name) ? image_name : strrchr(kernelcache_path, '/')+1));
    strcat(output_file, "-dump.dot");

    FILE *f = fopen(output_file, "w+");
    if (!f) {
        fprintf(stderr, "(!) Error: Unable to create output file.\n");
        return -3;
    }

    fwrite(DOT_DIGRAPH_DECLARATION_BEGIN "\n", strlen(DOT_DIGRAPH_DECLARATION_BEGIN)+1, 1, f);

    boolean_t wrote = false;

    if (image_name) {
        fprintf(stdout, "(+) Writing hierarchy for \'%s\' to file \'%s\'.\n", image_name, output_file);

        char *entries[256] = {0};
        uint32_t entries_count = 0;

        struct hierarchy_entry *p = NULL;
        SLIST_FOREACH(p, &head, entries) {
            if (strcmp(image_name, p->kext_name) == 0) {
                if (!wrote)
                    wrote = true;

                struct hierarchy_entry_head sub_head = SLIST_HEAD_INITIALIZER(sub_head);

                struct hierarchy_entry *prev = NULL;
                struct hierarchy_entry *curr = p;
                while (curr != NULL) {
                    struct hierarchy_entry *k = malloc(sizeof(struct hierarchy_entry));
                    strncpy(k->class_name, curr->class_name, sizeof(curr->class_name));
                    k->set = curr->set;
                    if (SLIST_EMPTY(&sub_head)) {
                        SLIST_INSERT_HEAD(&sub_head, k, entries);
                        prev = k;
                    } else {
                        SLIST_INSERT_AFTER(prev, k, entries);
                        prev = k;
                    }

                    curr = find_parent(&head, curr->set.reg_x2);
                }

                struct hierarchy_entry *j = NULL;
                SLIST_FOREACH(j, &sub_head, entries) {

                    boolean_t found = false;

                    for (uint32_t i = 0; i < entries_count; i++) {
                        if (strcmp(entries[i], j->class_name) == 0)
                            found = true;
                    }

                    if (!found) {
                        char dot_class_decl[512] = {0};
                        sprintf(dot_class_decl, DOT_CLASS_DECLARATION "\n", j->class_name, j->class_name);

                        fwrite(dot_class_decl, strlen(dot_class_decl), 1, f);

                        if (j->entries.sle_next) {
                            char dot_hierarchy_decl[512] = {0};
                            sprintf(dot_hierarchy_decl, DOT_HIERARCHY_DECLARTION "\n", j->class_name, j->entries.sle_next->class_name);
                            fwrite(dot_hierarchy_decl, strlen(dot_hierarchy_decl), 1, f);
                        }

                        entries[entries_count] = j->class_name;
                        entries_count++;
                    }
                }
            }
        }
    } else {
        fprintf(stderr, "(!) Warning: No image name specified. Dumping entire kernelcache.\n");
        struct hierarchy_entry *p = NULL;
        SLIST_FOREACH(p, &head, entries) {
            if (!wrote)
                wrote = true;

            char dot_class_string[512] = {0};
            sprintf(dot_class_string, DOT_CLASS_DECLARATION "\n", p->class_name, p->class_name);

            fwrite(dot_class_string, strlen(dot_class_string), 1, f);

            struct hierarchy_entry *parent = find_parent(&head, p->set.reg_x2);
            if (parent) {
                char dot_parent_string[512] = {0};
                sprintf(dot_parent_string, DOT_HIERARCHY_DECLARTION "\n", p->class_name, parent->class_name);

                fwrite(dot_parent_string, strlen(dot_parent_string), 1, f);
            }
        }
    }

    fwrite(DOT_DIGRAPH_DECLARATION_END, strlen(DOT_DIGRAPH_DECLARATION_END), 1, f);

    fflush(f);

    fclose(f);

    if (wrote) {
        fprintf(stdout, "(+) Done! Writing to \'%s\' was successful.\n", output_file);
    } else {
        fprintf(stderr, "(!) Error: Nothing was wrote to the output file \'%s\'. Please be sure that the image you named can be found in the kernelcache, and that it contains valid classes.\n", output_file);
        unlink(output_file);
    }

    if (wrote && auto_convert) {
        char cmd_string[256] = {0};
        sprintf(cmd_string, "dot %s -Tpdf -o %s.pdf", output_file, output_file);

        fprintf(stdout, "(+) Converting %s to PDF DOT graph...\n", output_file);

        system(cmd_string);
    }

    return 0;
}
