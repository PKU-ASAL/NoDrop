#include <stdint.h>
#include <string.h>
#include <stddef.h>

#include "mmheap.h"
#include "common.h"

#define INLINE __attribute__((always_inline)) inline
#define NOD_PTR_SANITY_CHECK(ptr)           \
    do {                                    \
    if (unlikely(!(ptr))) {                 \
        return NOD_OBJ_PTR_NULL;          \
    }}while(0)                              \


static nod_mmheap_ctl_t      nod_mmheap_ctl;

static int 
generic_fls(uint32_t x)
{
    int r = 32;
    if (!x)
        return 0;

    if (!(x & 0xffff0000u)) {
        x <<= 16;
        r -= 16;
    }
    if (!(x & 0xff000000u)) {
        x <<= 8;
        r -= 8;
    }
    if (!(x & 0xf0000000u)) {
        x <<= 4;
        r -= 4;
    }
    if (!(x & 0xc0000000u)) {
        x <<= 2;
        r -= 2;
    }
    if (!(x & 0x80000000u)) {
        x <<= 1;
        r -= 1;
    }
    return r;
}

static int 
__ffs(uint32_t word)
{
    return generic_fls(word & (~word + 1)) - 1;
}

static int 
__fls(uint32_t word)
{
    return generic_fls(word) - 1;
}

static void 
mapping_insert(size_t size, int *fli, int *sli)
{
    int fl, sl;

    if (size < NOD_MMHEAP_SMALL_BLOCK_SIZE) {
        /* Store small blocks in first list. */
        fl = 0;
        sl = (int)size / (NOD_MMHEAP_SMALL_BLOCK_SIZE / NOD_MMHEAP_SL_INDEX_COUNT);
    } else {
        fl = __fls(size);
        sl = ((int)size >> (fl - NOD_MMHEAP_SL_INDEX_COUNT_LOG2)) ^ (1 << NOD_MMHEAP_SL_INDEX_COUNT_LOG2);
        fl -= (NOD_MMHEAP_FL_INDEX_SHIFT - 1);
    }
    *fli = fl;
    *sli = sl;
}

/* This version rounds up to the next block size (for allocations) */
static void 
mapping_search(size_t size, int *fli, int *sli)
{
    size_t round;

    if (size >= NOD_MMHEAP_SMALL_BLOCK_SIZE) {
        round = (1 << (__fls(size) - NOD_MMHEAP_SL_INDEX_COUNT_LOG2)) - 1;
        size += round;
    }
    mapping_insert(size, fli, sli);
}

static INLINE size_t
blk_size(const nod_mmheap_blk_t *blk)
{
    return blk->size & NOD_MMHEAP_BLOCK_SIZE_MASK;
}

static INLINE int 
blk_is_last(const nod_mmheap_blk_t* blk)
{
	return blk_size(blk) == 0;
}

static INLINE void 
blk_set_size(nod_mmheap_blk_t *blk, size_t size)
{
    blk->size = size | (blk->size & NOD_MMHEAP_BLOCK_STATE_MASK);
}

static INLINE int 
blk_is_free(const nod_mmheap_blk_t *blk)
{
    return blk->size & NOD_MMHEAP_BLOCK_CURR_FREE;
}

static INLINE void 
blk_set_free(nod_mmheap_blk_t *blk)
{
    blk->size |= NOD_MMHEAP_BLOCK_CURR_FREE;
}

static INLINE void 
blk_set_used(nod_mmheap_blk_t *blk)
{
    blk->size &= ~NOD_MMHEAP_BLOCK_CURR_FREE;
}

static INLINE int 
blk_is_prev_free(const nod_mmheap_blk_t *blk)
{
    return blk->size & NOD_MMHEAP_BLOCK_PREV_FREE;
}

static INLINE void 
blk_set_prev_free(nod_mmheap_blk_t *blk)
{
    blk->size |= NOD_MMHEAP_BLOCK_PREV_FREE;
}

static void 
blk_set_prev_used(nod_mmheap_blk_t *blk)
{
    blk->size &= ~NOD_MMHEAP_BLOCK_PREV_FREE;
}

static INLINE nod_mmheap_blk_t *
blk_from_ptr(const void *ptr)
{
    return (nod_mmheap_blk_t *)((uint64_t)ptr - NOD_MMHEAP_BLK_START_OFFSET);
}

static INLINE void *
blk_to_ptr(const nod_mmheap_blk_t *blk)
{
    return (void *)((uint64_t)blk + NOD_MMHEAP_BLK_START_OFFSET);
}

/* Return location of next block after block of given size. */
static INLINE nod_mmheap_blk_t *
offset_to_blk(const void *ptr, int diff)
{
    return (nod_mmheap_blk_t *)((uint64_t)ptr + diff);
}

/* Return location of previous block. */
static INLINE nod_mmheap_blk_t *
blk_prev(const nod_mmheap_blk_t *blk)
{
    return blk->prev_phys_blk;
}

/* Return location of next existing block. */
static nod_mmheap_blk_t *
blk_next(const nod_mmheap_blk_t *blk)
{
    nod_mmheap_blk_t *next_blk;

    next_blk = offset_to_blk(blk_to_ptr(blk), blk_size(blk) - NOD_MMHEAP_BLK_HEADER_OVERHEAD);
    return next_blk;
}

/* Link a new block with its physical neighbor, return the neighbor. */
static nod_mmheap_blk_t *
blk_link_next(nod_mmheap_blk_t *blk)
{
    nod_mmheap_blk_t *next_blk;

    next_blk = blk_next(blk);
    next_blk->prev_phys_blk = blk;
    return next_blk;
}

static void 
blk_mark_as_free(nod_mmheap_blk_t *blk)
{
    nod_mmheap_blk_t *next_blk;

    /* Link the block to the next block, first. */
    next_blk = blk_link_next(blk);
    blk_set_prev_free(next_blk);
    blk_set_free(blk);
}

static void 
blk_mark_as_used(nod_mmheap_blk_t *blk)
{
    nod_mmheap_blk_t *next_blk;

    next_blk = blk_next(blk);
    blk_set_prev_used(next_blk);
    blk_set_used(blk);
}

static INLINE size_t 
align_up(size_t x, size_t align)
{
    return (x + (align - 1)) & ~(align - 1);
}

static INLINE size_t 
align_down(size_t x, size_t align)
{
    return x - (x & (align - 1));
}

static INLINE void *
align_ptr(const void *ptr, size_t align)
{
    return (void *)(((uint64_t)ptr + (align -1)) & ~(align -1));
}

/* Insert a free block into the free block list. */
static void 
insert_free_block(nod_mmheap_blk_t *blk, int fl, int sl)
{
    nod_mmheap_blk_t *curr;

    curr = nod_mmheap_ctl.blocks[fl][sl];
    blk->next_free = curr;
    blk->prev_free = &nod_mmheap_ctl.block_null;
    curr->prev_free = blk;

	/*
	** Insert the new block at the head of the list, and mark the first-
	** and second-level bitmaps appropriately.
	*/
    nod_mmheap_ctl.blocks[fl][sl] = blk;
    nod_mmheap_ctl.fl_bitmap |= (1 << fl);
    nod_mmheap_ctl.sl_bitmap[fl] |= (1 << sl);
}

/* Remove a free block from the free list.*/
static void 
remove_free_block(nod_mmheap_blk_t *blk, int fl, int sl)
{
    nod_mmheap_blk_t *prev_blk;
    nod_mmheap_blk_t *next_blk;

    prev_blk = blk->prev_free;
    next_blk = blk->next_free;
    next_blk->prev_free = prev_blk;
    prev_blk->next_free = next_blk;

    /* If this block is the head of the free list, set new head. */
    if (nod_mmheap_ctl.blocks[fl][sl] == blk) {
        nod_mmheap_ctl.blocks[fl][sl] = next_blk;

        /* If the new head is null, clear the bitmap. */
        if (next_blk == &nod_mmheap_ctl.block_null) {
            nod_mmheap_ctl.sl_bitmap[fl] &= ~(1 << sl);

            /* If the second bitmap is now empty, clear the fl bitmap. */
            if (!nod_mmheap_ctl.sl_bitmap[fl]) {
                nod_mmheap_ctl.fl_bitmap &= ~(1 << fl);
            }
        }
    }
}

/* Remove a given block from the free list. */
static void 
blk_remove(nod_mmheap_blk_t *blk)
{
    int fl, sl;

    mapping_insert(blk_size(blk), &fl, &sl);
    remove_free_block(blk, fl, sl);
}

/* Insert a given block into the free list. */
static void 
blk_insert(nod_mmheap_blk_t *blk)
{
    int fl, sl;

    mapping_insert(blk_size(blk), &fl, &sl);
    insert_free_block(blk, fl, sl);
}

static int 
blk_can_split(nod_mmheap_blk_t *blk, size_t size)
{
    return blk_size(blk) >= sizeof(nod_mmheap_blk_t) + size;
}

/* Split a block into two, the second of which is free. */
static nod_mmheap_blk_t *
blk_split(nod_mmheap_blk_t *blk, size_t size)
{
    nod_mmheap_blk_t   *remaining;
    size_t          remain_size;

    /* Calculate the amount of space left in the remaining block. */
    remaining   = offset_to_blk(blk_to_ptr(blk), size - NOD_MMHEAP_BLK_HEADER_OVERHEAD);
    remain_size = blk_size(blk) - (size + NOD_MMHEAP_BLK_HEADER_OVERHEAD);

    blk_set_size(remaining, remain_size);

    blk_set_size(blk, size);
    blk_mark_as_free(remaining);

    return remaining;
}

/* Absorb a free block's storage into an adjacent previous free block. */
static nod_mmheap_blk_t *
blk_absorb(nod_mmheap_blk_t *prev_blk, nod_mmheap_blk_t *blk)
{
    prev_blk->size += blk_size(blk) + NOD_MMHEAP_BLK_HEADER_OVERHEAD;
    blk_link_next(prev_blk);
    return prev_blk;
}

/* Merge a just-freed block with an adjacent previous free block. */
static nod_mmheap_blk_t *
blk_merge_prev(nod_mmheap_blk_t *blk)
{
    nod_mmheap_blk_t *prev_blk;

    if (blk_is_prev_free(blk)) {
        prev_blk = blk_prev(blk);
        blk_remove(prev_blk);
        blk = blk_absorb(prev_blk, blk);
    }

    return blk;
}

/* Merge a just-freed block with an adjacent free block. */
static nod_mmheap_blk_t *
blk_merge_next(nod_mmheap_blk_t *blk)
{
    nod_mmheap_blk_t *next_blk;

    next_blk = blk_next(blk);
    if (blk_is_free(next_blk)) {
        blk_remove(next_blk);
        blk = blk_absorb(blk, next_blk);
    }

    return blk;
}

/* Trim any trailing block space off the end of a block, return to pool. */
static void 
blk_trim_free(nod_mmheap_blk_t *blk, size_t size)
{
    nod_mmheap_blk_t *remaining_blk;

    if (blk_can_split(blk, size)) {
        remaining_blk = blk_split(blk, size);
        blk_link_next(blk);
        blk_set_prev_free(remaining_blk);
        blk_insert(remaining_blk);
    }
}

/* Trim any trailing block space off the end of a used block, return to pool. */
static void 
blk_trim_used(nod_mmheap_blk_t *blk, size_t size)
{
    nod_mmheap_blk_t *remaining_blk;

    if (blk_can_split(blk, size)) {
        /* If the next block is free, we must coalesce. */
        remaining_blk = blk_split(blk, size);
        blk_set_prev_used(remaining_blk);

        remaining_blk = blk_merge_next(remaining_blk);
        blk_insert(remaining_blk);
    }
}

static nod_mmheap_blk_t *
blk_trim_free_leading(nod_mmheap_blk_t *blk, size_t size)
{
    nod_mmheap_blk_t *remaining_blk;

    remaining_blk = blk;
    if (blk_can_split(blk, size)) {
        /* We want the 2nd block. */
        remaining_blk = blk_split(blk, size - NOD_MMHEAP_BLK_HEADER_OVERHEAD);
        blk_set_prev_free(remaining_blk);

        blk_link_next(blk);
        blk_insert(blk);
    }

    return remaining_blk;
}

static nod_mmheap_blk_t *
blk_search_suitable(int *fli, int *sli)
{
    int fl, sl;
    uint32_t sl_map, fl_map;

    fl = *fli;
    sl = *sli;

	/*
	** First, search for a block in the list associated with the given
	** fl/sl index.
	*/
    sl_map = nod_mmheap_ctl.sl_bitmap[fl] & (~0U << sl);
    if (!sl_map) {
        /* No block exists. Search in the next largest first-level list. */
        fl_map = nod_mmheap_ctl.fl_bitmap & (~0U << (fl + 1));
        if (!fl_map) {
            /* No free blocks available, memory has been exhausted. */
            return 0;
        }

        fl = __ffs(fl_map);
        *fli = fl;
        sl_map = nod_mmheap_ctl.sl_bitmap[fl];
    }
    sl = __ffs(sl_map);
    *sli = sl;

    /* Return the first block in the free list. */
    return nod_mmheap_ctl.blocks[fl][sl];
}

static nod_mmheap_blk_t *
blk_locate_free(size_t size)
{
    int fl = 0, sl = 0;
    nod_mmheap_blk_t *blk = NULL;

    if (!size) {
        return NULL;
    }

    mapping_search(size, &fl, &sl);

    /*
    ** mapping_search can futz with the size, so for excessively large sizes it can sometimes wind up
    ** with indices that are off the end of the block array.
    ** So, we protect against that here, since this is the only callsite of mapping_search.
    ** Note that we don't need to check sl, since it comes from a modulo operation that guarantees it's always in range.
    */
    if (fl < NOD_MMHEAP_FL_INDEX_COUNT) {
        blk = blk_search_suitable(&fl, &sl);
    }

    if (blk) {
        remove_free_block(blk, fl, sl);
    }

    return blk;
}

/*
** Adjust an allocation size to be aligned to word size, and no smaller
** than internal minimum.
*/
static size_t 
adjust_request_size(size_t size, size_t align)
{
    size_t adjust_size = 0;

    if (!size) {
        return 0;
    }

    adjust_size = align_up(size, align);
    if (!adjust_size || adjust_size > NOD_MMHEAP_BLK_SIZE_MAX) {
        return 0;
    }

    /* aligned sized must not exceed block_size_max or we'll go out of bounds on sl_bitmap */
    return adjust_size > NOD_MMHEAP_BLK_SIZE_MIN ? adjust_size : NOD_MMHEAP_BLK_SIZE_MIN;
}

static void *
blk_prepare_used(nod_mmheap_blk_t *blk, size_t size)
{
    if (!blk) {
        return NULL;
    }
    blk_trim_free(blk, size);
    blk_mark_as_used(blk);
    return blk_to_ptr(blk);
}

static INLINE int 
nod_mmheap_pool_is_full(void)
{
    return nod_mmheap_ctl.pool_cnt == NOD_MMHEAP_POOL_MAX;
}

static int 
nod_mmheap_pool_is_exist(void *pool_start)
{
    int i = 0;

    for (i = 0; i < nod_mmheap_ctl.pool_cnt; ++i) {
        if (nod_mmheap_ctl.pool_start[i] == pool_start) {
            return 1;
        }
    }
    return 0;
}

static INLINE void 
nod_mmheap_pool_record(void *pool_start)
{
    nod_mmheap_ctl.pool_start[nod_mmheap_ctl.pool_cnt++] = pool_start;
}

static void 
nod_mmheap_pool_unrecord(void *pool_start)
{
    int i = 0;

    for (i = 0; i < nod_mmheap_ctl.pool_cnt; ++i) {
        if (nod_mmheap_ctl.pool_start[i] == pool_start) {
            break;
        }
    }
    if (i != nod_mmheap_ctl.pool_cnt - 1) {
        nod_mmheap_ctl.pool_start[i] = nod_mmheap_ctl.pool_start[nod_mmheap_ctl.pool_cnt - 1];
    }
    --nod_mmheap_ctl.pool_cnt;
}

static void 
nod_mmheap_ctl_init(void)
{
    int i, j;

    nod_mmheap_ctl.pool_cnt = 0u;
    for (i = 0; i < NOD_MMHEAP_POOL_MAX; ++i) {
        nod_mmheap_ctl.pool_start[i] = (void *)NULL;
    }

    nod_mmheap_ctl.block_null.next_free = &nod_mmheap_ctl.block_null;
    nod_mmheap_ctl.block_null.prev_free = &nod_mmheap_ctl.block_null;

    nod_mmheap_ctl.fl_bitmap = 0;
    for (i = 0; i < NOD_MMHEAP_FL_INDEX_COUNT; ++i) {
        nod_mmheap_ctl.sl_bitmap[i] = 0;
        for (j = 0; j < NOD_MMHEAP_SL_INDEX_COUNT; ++j) {
            nod_mmheap_ctl.blocks[i][j] = &nod_mmheap_ctl.block_null;
        }
    }
}

int 
nod_mmheap_init(void *pool_start, size_t pool_size)
{
    nod_mmheap_ctl_init();

    return nod_mmheap_pool_add(pool_start, pool_size);
}

void *
nod_mmheap_alloc(size_t size)
{
    size_t          adjust_size;
    nod_mmheap_blk_t   *blk;

    if (size > NOD_MMHEAP_BLK_SIZE_MAX) {
        return NULL;
    }

    adjust_size     = adjust_request_size(size, NOD_MMHEAP_ALIGN_SIZE);
    blk             = blk_locate_free(adjust_size);
    if (!blk) {
        return NULL;
    }

    return blk_prepare_used(blk, adjust_size);
}

void *
nod_mmheap_calloc(size_t num, size_t size)
{
    void *ptr;

    ptr = nod_mmheap_alloc(num * size);
    if (ptr) {
        memset(ptr, 0, num * size);
    }

    return ptr;
}

void *
nod_mmheap_aligned_alloc(size_t size, size_t align)
{
    nod_mmheap_blk_t *blk;
    void *ptr, *aligned, *next_aligned;
    size_t adjust_size, aligned_size;
    size_t gap_minimum, size_with_gap, gap, gap_remain, offset;

    adjust_size     = adjust_request_size(size, NOD_MMHEAP_ALIGN_SIZE);
    gap_minimum     = sizeof(nod_mmheap_blk_t);
    size_with_gap   = adjust_request_size(adjust_size + align + gap_minimum, align);
    aligned_size    = (adjust_size && align > NOD_MMHEAP_ALIGN_SIZE) ? size_with_gap : adjust_size;

    blk = blk_locate_free(aligned_size);
    if (!blk) {
        return NULL;
    }

    ptr = blk_to_ptr(blk);
    aligned = align_ptr(ptr, align);
    gap = (size_t)((uint64_t)aligned - (uint64_t)ptr);

    if (gap && gap < gap_minimum) {
        gap_remain = gap_minimum - gap;
        offset = gap_remain > align ? gap_remain : align;
        next_aligned = (void *)((uint64_t)aligned + offset);

        aligned = align_ptr(next_aligned, align);
        gap = (size_t)((uint64_t)aligned - (uint64_t)ptr);
    }

    if (gap) {
        blk = blk_trim_free_leading(blk, gap);
    }

    return blk_prepare_used(blk, adjust_size);
}

void 
nod_mmheap_free(void *ptr)
{
    nod_mmheap_blk_t *blk;

    if (!ptr) {
        return;
    }

    blk = blk_from_ptr(ptr);
    blk_mark_as_free(blk);
    blk = blk_merge_prev(blk);
    blk = blk_merge_next(blk);
    blk_insert(blk);
}

void *
nod_mmheap_realloc(void *ptr, size_t size)
{
    void *p = 0;
    nod_mmheap_blk_t *curr_blk, *next_blk;
    size_t curr_size, combined_size, adjust_size, min_size;

    if (ptr && size == 0) {
        nod_mmheap_free(ptr);
        return NULL;
    }

    if (!ptr) {
        return nod_mmheap_alloc(size);
    }

    curr_blk = blk_from_ptr(ptr);
    next_blk = blk_next(curr_blk);

    curr_size = blk_size(curr_blk);
    combined_size = curr_size + blk_size(next_blk) + NOD_MMHEAP_BLK_HEADER_OVERHEAD;
    adjust_size = adjust_request_size(size, NOD_MMHEAP_ALIGN_SIZE);

    if (adjust_size > curr_size && (!blk_is_free(next_blk) || adjust_size > combined_size)) {
        p = nod_mmheap_alloc(size);
        if (p) {
            min_size = curr_size < size ? curr_size : size;
            memcpy(p, ptr, min_size);
            nod_mmheap_free(ptr);
        }
    } else {
        if (adjust_size > curr_size) {
            blk_merge_next(curr_blk);
            blk_mark_as_used(curr_blk);
        }

        blk_trim_used(curr_blk, adjust_size);
        p = ptr;
    }

    return p;
}

int 
nod_mmheap_pool_add(void *pool_start, size_t pool_size)
{
    nod_mmheap_blk_t   *curr_blk;
    nod_mmheap_blk_t   *next_blk;
    size_t          size_aligned;

    if (nod_mmheap_pool_is_full()) {
        return NOD_MMHEAP_POOL_OVERFLOW;
    }

    if (nod_mmheap_pool_is_exist(pool_start)) {
        return NOD_MMHEAP_POOL_ALREADY_EXIST;
    }

    size_aligned = align_down(pool_size - 2 * NOD_MMHEAP_BLK_HEADER_OVERHEAD, NOD_MMHEAP_ALIGN_SIZE);

    if (((uint64_t)pool_start % NOD_MMHEAP_ALIGN_SIZE) != 0u) {
        return NOD_MMHEAP_INVALID_POOL_ADDR;
    }

    if (size_aligned < NOD_MMHEAP_BLK_SIZE_MIN ||
        size_aligned > NOD_MMHEAP_BLK_SIZE_MAX) {
        return NOD_MMHEAP_INVALID_POOL_SIZE;
    }

    /*
     ** Create the main free block. Offset the start of the block slightly
     ** so that the prev_phys_block field falls outside of the pool -
     ** it will never be used.
     */
    curr_blk = offset_to_blk(pool_start, -(int)NOD_MMHEAP_BLK_HEADER_OVERHEAD);
    blk_set_size(curr_blk, size_aligned);
    blk_set_free(curr_blk);
    blk_set_prev_used(curr_blk);
    blk_insert(curr_blk);

    /* Split the block to create a zero-size sentinel block. */
    next_blk = blk_link_next(curr_blk);
    blk_set_size(next_blk, 0);
    blk_set_used(next_blk);
    blk_set_prev_free(next_blk);

    nod_mmheap_pool_record(pool_start);

    return 0;
}

int 
nod_mmheap_pool_rmv(void *pool_start)
{
    int fl = 0, sl = 0;
    nod_mmheap_blk_t *blk;

    NOD_PTR_SANITY_CHECK(pool_start);

    if (!nod_mmheap_pool_is_exist(pool_start)) {
        return NOD_MMHEAP_POOL_NOT_EXIST;
    }

    blk = offset_to_blk(pool_start, -(int)NOD_MMHEAP_BLK_HEADER_OVERHEAD);
    mapping_insert(blk_size(blk), &fl, &sl);
    remove_free_block(blk, fl, sl);

    nod_mmheap_pool_unrecord(pool_start);
    return 0;
}

int 
nod_mmheap_pool_check(void *pool_start, nod_mmheap_info_t *info)
{
    nod_mmheap_blk_t* blk;

    NOD_PTR_SANITY_CHECK(pool_start);
    NOD_PTR_SANITY_CHECK(info);

    memset(info, 0, sizeof(nod_mmheap_info_t));

    blk = offset_to_blk(pool_start, -(int)NOD_MMHEAP_BLK_HEADER_OVERHEAD);

    while (blk && !blk_is_last(blk)) {
        if (blk_is_free(blk)) {
            info->free += blk_size(blk);
        } else {
            info->used += blk_size(blk);
        }
        blk = blk_next(blk);
    }

    return 0;
}

int 
nod_mmheap_check(nod_mmheap_info_t *info)
{
    int i;
    int err;
    nod_mmheap_info_t pool_info;

    NOD_PTR_SANITY_CHECK(info);

    memset(info, 0, sizeof(nod_mmheap_info_t));

    for (i = 0; i < nod_mmheap_ctl.pool_cnt; ++i) {
        err = nod_mmheap_pool_check(nod_mmheap_ctl.pool_start[i], &pool_info);
        if (err != 0) {
            return err;
        }

        info->free += pool_info.free;
        info->used += pool_info.used;
    }

    return 0;
}