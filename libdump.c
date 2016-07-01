//
//  libdump.c
//  iokit-dumper-AArch64
//
//  Created by jndok on 30/06/16.
//  Copyright © 2016 jndok. All rights reserved.
//

#include "libdump.h"

struct hierarchy_entry *prev = NULL;

static struct hierarchy_entry *find_parent(struct hierarchy_entry_head *head, uint64_t x2)
{
    struct hierarchy_entry *p = NULL;
    SLIST_FOREACH(p, head, entries) {
        if (p->set.reg_x0 == x2 && x2 != 0) {
            return p;
        }
    }
    
    return NULL;
}

void rebuild_hierarchy(struct hierarchy_entry_head *head)
{
    if (SLIST_EMPTY(head))
        return;
    
    struct hierarchy_entry *p = NULL;
    SLIST_FOREACH(p, head, entries) {
        
        struct hierarchy_entry_head sub_head = SLIST_HEAD_INITIALIZER(sub_head);
        
        struct hierarchy_entry *curr = p;
        while (curr != NULL) {
            struct hierarchy_entry *k = malloc(sizeof(struct hierarchy_entry));
            strncpy(k->class_name, curr->class_name, sizeof(curr->class_name));
            k->set = curr->set;
            SLIST_INSERT_HEAD(&sub_head, k, entries);
            
            curr = find_parent(head, curr->set.reg_x2);
        }
        printf("\n");
        
        struct hierarchy_entry *j = NULL;
        SLIST_FOREACH(j, &sub_head, entries) {
            printf("%s", j->class_name);
            if (j->entries.sle_next) {
                printf(" -> ");
            }
        }
        
        //printf("\n");
    }
}

dmp_ctx_t *init_dump_ctx(macho_map_t *map)
{
    dmp_ctx_t *ctx = malloc(sizeof(dmp_ctx_t));
    
    reg_map_t *reg_map = malloc(sizeof(reg_map_t));
    bzero(reg_map, sizeof(reg_map_t));
    
    set_ctx_map(ctx, map);
    set_ctx_image(ctx, NULL);
    set_ctx_reg_map(ctx, reg_map);
    
    return ctx;
}

void emulate_constructor(dmp_ctx_t *ctx, uint64_t constructor_address, struct hierarchy_entry_head *head)
{
    if (!ctx)
        return;
    if (!ctx->kimage_mh || !ctx->map || !ctx->reg_map)
        return;
    
    uint64_t kimage_base = find_kimage_base(ctx->kimage_mh);
    uint64_t kimage_os_metaclass_constructor = find_kimage_os_metaclass_constructor(ctx->kimage_mh, kimage_base);
    
    csh handle;
    cs_insn *insn;
    size_t count;
    
    cs_regs regs_read = {0}, regs_write = {0};
    uint8_t read_count, write_count;
    
    if (cs_open(CS_ARCH_ARM64, CS_MODE_ARM, &handle) != CS_ERR_OK)
        return;
    
    cs_option(handle, CS_OPT_DETAIL, CS_OPT_ON);
    
    uint8_t *constructor_code = (uint8_t *)KERNEL_ADDR_TO_MAP(ctx->kimage_mh, kimage_base, constructor_address);
    uint64_t constructor_size = get_constructor_size(ctx->kimage_mh, constructor_address, kimage_base);
    
    count = cs_disasm(handle, constructor_code, constructor_size, constructor_address, 0, &insn);
    if (count > 0) {
        size_t j;
        for (j = 0; j < count; j++) {
            if (cs_regs_access(handle, &insn[j], regs_read, &read_count, regs_write, &write_count) == 0) {
                switch (insn[j].id) {
                        /* ADR: calculate offset, add to pc */
                    case ARM64_INS_ADR: {
                        
                        uint64_t adr_addr = 0;
                        int is_adrp = 0;
                        uint32_t rd = 0;
                        int32_t off = 0;
                        if (aarch64_decode_adr(*(uint32_t *)(&insn[j].bytes), &is_adrp, &rd, &off)) {
                            adr_addr = insn[j].address + off;
                        }
                        
                        get_ctx_reg_map_reg(ctx, regs_write[0]) = adr_addr;
                        break;
                    }
                        
                        /* ADRP: calculate offset, add to pc, zero out last 12 bits */
                    case ARM64_INS_ADRP: {
                        
                        uint64_t adr_addr = 0;
                        int is_adrp = 0;
                        uint32_t rd = 0;
                        int32_t off = 0;
                        if (aarch64_decode_adr(*(uint32_t *)(&insn[j].bytes), &is_adrp, &rd, &off)) {
                            adr_addr = ((insn[j].address + off) >> 12) << 12;
                        }
                        
                        get_ctx_reg_map_reg(ctx, regs_write[0]) = adr_addr;
                        break;
                    }
                        
                        /* LDR: calculate offset, add to pc, deref that, write result in write reg */
                    case ARM64_INS_LDR: {
                        
                        uint64_t ldr_addr = 0;
                        int is_w = 0;
                        int is64 = 0;
                        uint32_t rt = 0;
                        
                        int32_t s_off = 0;
                        uint32_t u_off = 0;
                        
                        if (aarch64_decode_ldr_literal(*(uint32_t *)(&insn[j].bytes), &is_w, &is64, &rt, &s_off)) {
                            ldr_addr = insn[j].address + s_off;
                            uint64_t ldr_deref = *(uint64_t *)KERNEL_ADDR_TO_MAP(ctx->kimage_mh, kimage_base, ldr_addr);
                            get_ctx_reg_map_reg(ctx, regs_write[0]) = ldr_deref;
                        } else if (aarch64_decode_ldr_immediate(*(uint32_t *)(&insn[j].bytes), &u_off)) {
                            uint64_t op1 = get_ctx_reg_map_reg(ctx, regs_read[0]);
                            op1 += u_off;
                            
                            uint64_t ldr_addr = *(uint64_t *)KERNEL_ADDR_TO_MAP(ctx->kimage_mh, kimage_base, op1);
                            get_ctx_reg_map_reg(ctx, regs_write[0]) = ldr_addr;
                        }
                        
                        break;
                    }
                        
                        /* ADD: take value in read reg, add to value in write reg, add immediate to value in write reg */
                    case ARM64_INS_ADD: {

                        uint32_t off = 0;
                        if (aarch64_decode_add(*(uint32_t *)(&insn[j].bytes), &off)) {
                            uint64_t op1 = get_ctx_reg_map_reg(ctx, regs_read[0]);
                            op1 += off;
                            get_ctx_reg_map_reg(ctx, regs_write[0]) = op1;
                        }
                        
                        break;
                    }
                        
                        /* MOV: take value in read reg, set to value in write reg */
                    case ARM64_INS_MOV: {
                        
                        uint64_t op1 = get_ctx_reg_map_reg(ctx, regs_read[0]);
                        get_ctx_reg_map_reg(ctx, regs_write[0]) = op1;
                        
                        break;
                    }
                        
                    /* BL: not actually emulated, used as a breakpoint to load registers into the hierarchy list */
                    case ARM64_INS_BL: {
                        
                        int is_bl = 0;
                        int32_t off = 0;
                        if (aarch64_decode_b(*(uint32_t *)(&insn[j].bytes), &is_bl, &off)) {
                            if (insn[j].address + off == kimage_os_metaclass_constructor) {

                                struct hierarchy_entry *entry = malloc(sizeof(struct hierarchy_entry));
                                
                                strncpy(entry->class_name, (char *)KERNEL_ADDR_TO_MAP(ctx->kimage_mh, kimage_base, get_ctx_reg_map_reg(ctx, REG_X1)), sizeof(entry->class_name));
                                
                                struct hierarchy_regs_set set = {0};
                                set.reg_x0 = get_ctx_reg_map_reg(ctx, REG_X0);
                                set.reg_x1 = get_ctx_reg_map_reg(ctx, REG_X1);
                                set.reg_x2 = get_ctx_reg_map_reg(ctx, REG_X2);
                                
                                entry->set = set;
                                
                                if (SLIST_EMPTY(head)) {
                                    SLIST_INSERT_HEAD(head, entry, entries);
                                    prev = entry;
                                } else {
                                    SLIST_INSERT_AFTER(prev, entry, entries);
                                    prev = entry;
                                }
                                
#if 0
                                printf("x0: %#llx\n", get_ctx_reg_map_reg(ctx, REG_X0));
                                printf("x1: %#llx -> %s\n", get_ctx_reg_map_reg(ctx, REG_X1), (char *)KERNEL_ADDR_TO_MAP(ctx->kimage_mh, kimage_base, get_ctx_reg_map_reg(ctx, REG_X1)));
                                printf("x2: %#llx\n", get_ctx_reg_map_reg(ctx, REG_X2));
                                
                                printf("\n");
#endif
                            }
                        }
                        
                        break;
                    }
                    
                }
            }
        }
    }
    
    clean_ctx_reg_map(ctx);
}