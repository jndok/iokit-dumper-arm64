//
//  libdump.h
//  iokit-dumper-AArch64
//
//  Created by jndok on 30/06/16.
//  Copyright © 2016 jndok. All rights reserved.
//

#ifndef libdump_h
#define libdump_h

#include <stdio.h>
#include <stdlib.h>
#include <sys/queue.h>

#include <capstone/capstone.h>
#include <machoman/machoman.h>

#include "parser.h"

#define REG_X0  199
#define REG_X1  200
#define REG_X2  201
#define REG_X3  202
#define REG_X4  203
#define REG_X5  204
#define REG_X6  205
#define REG_X7  206
#define REG_X8  207
#define REG_X9  208
#define REG_X10 209
#define REG_X11 210
#define REG_X12 211
#define REG_X13 212
#define REG_X14 213
#define REG_X15 214
#define REG_X16 215
#define REG_X17 216
#define REG_X18 217
#define REG_X19 218
#define REG_X20 219
#define REG_X21 220
#define REG_X22 221
#define REG_X23 222
#define REG_X24 223
#define REG_X25 224
#define REG_X26 225
#define REG_X27 226
#define REG_X28 227
#define REG_X29 1
#define REG_X30 2

#define set_ctx_map(ctx, map)           do { if (ctx) { ctx->map        = (map)     ?   map     :   NULL; } } while(0); // set context emulation map
#define set_ctx_reg_map(ctx, reg_map)   do { if (ctx) { ctx->reg_map    = (reg_map) ?   reg_map :   NULL; } } while(0); // set context registers map
#define set_ctx_image(ctx, image)       do { if (ctx) { ctx->kimage_mh  = (image)   ?   image   :   NULL; } } while(0); // set context emulation image

#define get_ctx_reg_map_reg(ctx, reg_id) (ctx->reg_map->regs[reg_id])

#define clean_ctx_reg_map(ctx)          do { if (ctx) { bzero(ctx->reg_map, sizeof(reg_map_t)); } } while(0);

/* https://github.com/aquynh/capstone/blob/8bd53811b5c7de65974f3ab82020c99b2ce407d9/arch/AArch64/AArch64Mapping.c */
typedef struct reg_map {
    uint64_t regs[261];
} reg_map_t;

/* emulation context */
typedef struct dmp_ctx {
    macho_map_t *map;
    reg_map_t *reg_map;
    struct mach_header_64 *kimage_mh;
} dmp_ctx_t;

typedef struct hierarchy_regs_set {
    uint64_t reg_x0;
    uint64_t reg_x1;
    uint64_t reg_x2;
} hierarchy_regs_set_t;

struct hierarchy_entry {
    SLIST_ENTRY(hierarchy_entry) entries;
    char class_name[128];
    struct hierarchy_regs_set set;
};

SLIST_HEAD(hierarchy_entry_head, hierarchy_entry);

/* hierarchy */
struct hierarchy_entry *find_parent(struct hierarchy_entry_head *head, uint64_t x2);

/* emulation */
dmp_ctx_t *init_dump_ctx(macho_map_t *map);
void emulate_constructor(dmp_ctx_t *ctx, uint64_t constructor_address, struct hierarchy_entry_head *head);


#endif /* libdump_h */
