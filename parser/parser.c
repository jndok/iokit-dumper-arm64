//
//  parser.c
//  iokit-dumper-AArch64
//
//  Created by jndok on 30/06/16.
//  Copyright © 2016 jndok. All rights reserved.
//

#include "parser.h"

char *read_line(FILE *fin) {
    char *buffer;
    char *tmp;
    int read_chars = 0;
    int bufsize = 512;
    char *line = malloc(bufsize);

    if ( !line ) {
        return NULL;
    }

    buffer = line;

    while ( fgets(buffer, bufsize - read_chars, fin) ) {
        read_chars = (int)strlen(line);

        if ( line[read_chars - 1] == '\n' ) {
            line[read_chars - 1] = '\0';
            return line;
        }

        else {
            bufsize = 2 * bufsize;
            tmp = realloc(line, bufsize);
            if ( tmp ) {
                line = tmp;
                buffer = line + read_chars;
            }
            else {
                free(line);
                return NULL;
            }
        }
    }
    return NULL;
}

static int32_t extract_signed_bitfield(uint32_t insn, unsigned width, unsigned offset)
{
    unsigned shift_l = sizeof (int32_t) * 8 - (offset + width);
    unsigned shift_r = sizeof (int32_t) * 8 - width;

    return ((int32_t) insn << shift_l) >> shift_r;
}

static int decode_masked_match(uint32_t insn, uint32_t mask, uint32_t pattern)
{
    return (insn & mask) == pattern;
}

int aarch64_decode_adr (uint32_t insn, int *is_adrp, unsigned *rd, int32_t *offset)
{
    /* adr  0ii1 0000 iiii iiii iiii iiii iiir rrrr */
    /* adrp 1ii1 0000 iiii iiii iiii iiii iiir rrrr */
    if (decode_masked_match (insn, 0x1f000000, 0x10000000))
    {
        uint32_t immlo = (insn >> 29) & 0x3;
        int32_t immhi = extract_signed_bitfield (insn, 19, 5) << 2;

        *is_adrp = (insn >> 31) & 0x1;
        *rd = (insn >> 0) & 0x1f;

        if (*is_adrp)
        {
            /* The ADRP instruction has an offset with a -/+ 4GB range,
             encoded as (immhi:immlo * 4096).  */
            *offset = (immhi | immlo) * 4096;
        }
        else
            *offset = (immhi | immlo);

        return 1;
    }
    return 0;
}

int aarch64_decode_ldr_literal (uint32_t insn, int *is_w, int *is64, unsigned *rt, int32_t *offset)
{
    /* LDR    0T01 1000 iiii iiii iiii iiii iiir rrrr */
    /* LDRSW  1001 1000 iiii iiii iiii iiii iiir rrrr */
    if ((insn & 0x3f000000) == 0x18000000)
    {
        *is_w = (insn >> 31) & 0x1;

        if (*is_w)
        {
            /* LDRSW always takes a 64-bit destination registers.  */
            *is64 = 1;
        }
        else
            *is64 = (insn >> 30) & 0x1;

        *rt = (insn >> 0) & 0x1f;
        *offset = extract_signed_bitfield (insn, 19, 5) << 2;

        return 1;
    }

    return 0;
}

int aarch64_decode_ldr_immediate(uint32_t insn, uint32_t *offset)
{
    if ((insn & 0xF9400040) == 0xF9400040) {
        *offset = ((insn << 10) >> 20) << 0x3;

        return 1;
    }
    return 0;
}

int aarch64_decode_add (uint32_t insn, uint32_t *offset)
{
    /* x00x 0001 SSii iiii iiii iinn nnnd dddd */

    *offset = (insn << 10) >> 20;

    return 1;
}

int aarch64_decode_b(uint32_t insn, int *is_bl, int32_t *offset)
{
    /* b  0001 01ii iiii iiii iiii iiii iiii iiii */
    /* bl 1001 01ii iiii iiii iiii iiii iiii iiii */
    if (decode_masked_match (insn, 0x7c000000, 0x14000000))
    {
        *is_bl = (insn >> 31) & 0x1;
        *offset = extract_signed_bitfield (insn, 26, 0) << 2;

        return 1;
    }
    return 0;
}

uint32_t get_constructor_size(struct mach_header_64 *mh, uint64_t constructor_kaddr, uint64_t kbase)
{
    if (!constructor_kaddr)
        return 0;
    for (uint32_t sz = 0 ;; sz++) {
        if (*(uint32_t *)MAP_ADDR_SLIDE(mh, KERNEL_ADDR_UNSLIDE(kbase, (constructor_kaddr + sz))) == INSN_RET) {
            return sz + 4;
        } else if (*(uint32_t *)MAP_ADDR_SLIDE(mh, KERNEL_ADDR_UNSLIDE(kbase, (constructor_kaddr + sz))) == INSN_PROLOG_END) {
            return sz + 8;
        }

    }
}

uint64_t find_kimage_base(struct mach_header_64 *mh)
{
    struct segment_command_64 *seg_text = find_segment_command64(mh, SEG_TEXT);
    if (seg_text)
        return seg_text->vmaddr;

    return 0;
}

/*
 Credits for original identification method to morpheus (Jonathan Levin).
 */
const char *get_kext_name(macho_map_t *map, struct mach_header_64 *mh)
{
    void *p = NULL;
    const char *z = NULL;
    const char *kext_name = NULL;

    struct segment_command_64 *seg_data = find_segment_command64(mh, SEG_DATA);
    if (!seg_data) {
        return NULL;
    }

    struct section_64 *sect_data = find_section64(seg_data, SECT_DATA);
    if (!sect_data)
        return NULL;

    uint32_t sect_data_off = sect_data->offset;
    uint64_t sect_data_size = sect_data->size;

    if (sect_data_off && sect_data_size) {
        if (((void *)mh + sect_data_off + sect_data_size) >= (map->map_data + map->map_size))
            return NULL;

        p = memmem((const void *)((void *)mh + sect_data_off), sect_data_size, "com.apple.", 10);

        while (p) {
            if (p > (void *)((void *)mh + sect_data_off + sect_data_size))
                return NULL;

            z = (const char *)p;
            p = memmem((char *)p + 1, sect_data_size, "com.apple.", 10);
        }

        kext_name = z;
    } else
        return NULL;

    if (kext_name) {
        if (strlen(kext_name) > 128)
            kext_name = NULL;
    }

    return kext_name;
}

uint64_t find_kimage_os_metaclass_constructor(struct mach_header_64 *mh, uint64_t kimage_base)
{
    struct segment_command_64 *seg_data = find_segment_command64(mh, SEG_DATA);
    if (!seg_data)
        return -1;

    struct section_64 *sect_mod_init_func = find_section64(seg_data, "__mod_init_func");
    if (!sect_mod_init_func)
        return -1;

    uint64_t sect_mod_init_func_off = sect_mod_init_func->offset;
    uint64_t sect_mod_init_func_size = sect_mod_init_func->size;

    uint64_t os_metaclass_constructor = 0;

    uint32_t n_ptrs = (uint32_t)(sect_mod_init_func_size / sizeof(uint64_t));
    uint32_t read_ptrs = 0;

    uint64_t os_metaclass_candidates[64] = {0};
    uint32_t candidates_index = 0;

    for (uint64_t *p = (uint64_t *)((void *)mh + sect_mod_init_func_off); p < (uint64_t *)((void *)mh + sect_mod_init_func_off + sect_mod_init_func_size); p++) {
        uint32_t *curr_constructor_code = (uint32_t *)KERNEL_ADDR_TO_MAP(mh, kimage_base, *p);
        uint64_t curr_constructor_size = get_constructor_size((struct mach_header_64 *)mh, *p, kimage_base);
        if (curr_constructor_size <= 64) {
            for (uint32_t *k = curr_constructor_code; k < (curr_constructor_code + (curr_constructor_size / sizeof(uint32_t))); k++) {
                int is_bl = 0;
                int32_t off = 0;
                if (aarch64_decode_b(*k, &is_bl, &off)) {
                    if (is_bl) {
                        uint64_t curr_pc = MAP_ADDR_TO_KERNEL(mh, kimage_base, k);
                        os_metaclass_constructor = curr_pc + off;

                        return os_metaclass_constructor;
                    }
                }
            }
        }
    }

    // if we are here, it means the kext doesn't have any normal sized constructors...

    for (uint64_t *p = (uint64_t *)((void *)mh + sect_mod_init_func_off); p < (uint64_t *)((void *)mh + sect_mod_init_func_off + sect_mod_init_func_size); p++, read_ptrs++) {
        if (!*p)
            return -1;

        if (n_ptrs > 1) {
            if (read_ptrs == 2)
                break;
        } else if (n_ptrs == 1) {
            if (read_ptrs == 1) {
                break;
            }
        }

        uint32_t *curr_constructor_code = (uint32_t *)KERNEL_ADDR_TO_MAP(mh, kimage_base, *p);
        uint64_t curr_constructor_size = get_constructor_size((struct mach_header_64 *)mh, *p, kimage_base);

        for (uint32_t *k = curr_constructor_code; k < (curr_constructor_code + (curr_constructor_size / sizeof(uint32_t))); k++) {
            int is_bl = 0;
            int32_t off = 0;
            if (aarch64_decode_b(*k, &is_bl, &off)) {
                if (is_bl) {
                    uint64_t curr_pc = MAP_ADDR_TO_KERNEL(mh, kimage_base, k);
                    if (*(k-1) != INSN_NOP) { // XXX: stopgap, must be properly fixed
                        os_metaclass_candidates[candidates_index] = curr_pc + off;
                        candidates_index++;
                    }
                }
            }
        }
    }

    struct candidates_table {
        uint64_t candidate;
        uint32_t occurences;
    } table[32] = {0};
    uint32_t table_index = 0;

    for (uint32_t i = 0; i < candidates_index; i++) {
        boolean_t found_in_table = FALSE;
        for (uint32_t k = 0; k < 32; k++) {
            if (table[k].candidate == os_metaclass_candidates[i]) {
                found_in_table = TRUE;
                table[k].occurences++;
            }
        }

        if (!found_in_table) {
            table[table_index].candidate = os_metaclass_candidates[i];
            table[table_index].occurences++;
            table_index++;
        }
    }

    uint32_t highest_occurrences = 0;
    for (uint32_t i=0; i < table_index; i++) {
        if (table[i].occurences > highest_occurrences) {
            os_metaclass_constructor = table[i].candidate; // and we have a winner! :P
            highest_occurrences = table[i].occurences;
        }
    }

    return os_metaclass_constructor;
}
