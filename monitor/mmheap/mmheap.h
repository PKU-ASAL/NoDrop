#ifndef NOD_MMHEAP_H_
#define NOD_MMHEAP_H_

#define nod_mmheap_alloc            malloc
#define nod_mmheap_calloc           calloc
#define nod_mmheap_realloc          realloc
#define nod_mmheap_free             free

#define OFFSET_OF_FIELD(type, field)    \
    ((uint64_t)&(((type *)0)->field))

#define NOD_MMHEAP_NONE                0
#define NOD_MMHEAP_POOL_OVERFLOW      -1
#define NOD_MMHEAP_POOL_ALREADY_EXIST -2
#define NOD_MMHEAP_INVALID_POOL_ADDR  -3
#define NOD_MMHEAP_INVALID_POOL_SIZE  -4
#define NOD_MMHEAP_POOL_NOT_EXIST     -5
#define NOD_OBJ_PTR_NULL              -6

/**
 * log2 of number of linear subdivisions of block sizes. Larger
 * values require more memory in the control structure. Values of
 * 4 or 5 are typical.
 */
#define NOD_MMHEAP_SL_INDEX_COUNT_LOG2    5

/* All allocation sizes and addresses are aligned to 4 bytes. */
#define NOD_MMHEAP_ALIGN_SIZE_LOG2        2
#define NOD_MMHEAP_ALIGN_SIZE             (1 << NOD_MMHEAP_ALIGN_SIZE_LOG2)

/*
 * We support allocations of sizes up to (1 << NOD_MMHEAP_FL_INDEX_MAX) bits.
 * However, because we linearly subdivide the second-level lists, and
 * our minimum size granularity is 4 bytes, it doesn't make sense to
 * create first-level lists for sizes smaller than NOD_MMHEAP_SL_INDEX_COUNT * 4,
 * or (1 << (NOD_MMHEAP_SL_INDEX_COUNT_LOG2 + 2)) bytes, as there we will be
 * trying to split size ranges into more slots than we have available.
 * Instead, we calculate the minimum threshold size, and place all
 * blocks below that size into the 0th first-level list.
 */
#define NOD_MMHEAP_FL_INDEX_MAX           30
#define NOD_MMHEAP_SL_INDEX_COUNT         (1 << NOD_MMHEAP_SL_INDEX_COUNT_LOG2)
#define NOD_MMHEAP_FL_INDEX_SHIFT         (NOD_MMHEAP_SL_INDEX_COUNT_LOG2 + NOD_MMHEAP_ALIGN_SIZE_LOG2)
#define NOD_MMHEAP_FL_INDEX_COUNT         (NOD_MMHEAP_FL_INDEX_MAX - NOD_MMHEAP_FL_INDEX_SHIFT + 1)

#define NOD_MMHEAP_SMALL_BLOCK_SIZE       (1 << NOD_MMHEAP_FL_INDEX_SHIFT)

#define NOD_MMHEAP_BLOCK_CURR_FREE        (1 << 0)
#define NOD_MMHEAP_BLOCK_PREV_FREE        (1 << 1)
#define NOD_MMHEAP_BLOCK_SIZE_MASK        ~(NOD_MMHEAP_BLOCK_CURR_FREE | NOD_MMHEAP_BLOCK_PREV_FREE)
#define NOD_MMHEAP_BLOCK_STATE_MASK       (NOD_MMHEAP_BLOCK_CURR_FREE | NOD_MMHEAP_BLOCK_PREV_FREE)

typedef struct nod_mmheap_information_st {
    uint32_t    used; /* space is used */
    uint32_t    free; /* space is free */
} nod_mmheap_info_t;

/**
 * Block structure.
 *
 * There are several implementation subtleties involved:
 * - The prev_phys_block field is only valid if the previous block is free.
 * - The prev_phys_block field is actually stored at the end of the
 *   previous block. It appears at the beginning of this structure only to
 *   simplify the implementation.
 * - The next_free / prev_free fields are only valid if the block is free.
 */
typedef struct nod_mmheap_blk_st {
    struct nod_mmheap_blk_st *prev_phys_blk;

    size_t size;

    struct nod_mmheap_blk_st *next_free;
    struct nod_mmheap_blk_st *prev_free;
} nod_mmheap_blk_t;

/**
 * A free block must be large enough to store its header minus the size of
 * the prev_phys_block field, and no larger than the number of addressable
 * bits for FL_INDEX.
 */
#define NOD_MMHEAP_BLK_SIZE_MIN           (sizeof(nod_mmheap_blk_t) - sizeof(nod_mmheap_blk_t *))
#define NOD_MMHEAP_BLK_SIZE_MAX           (1 << NOD_MMHEAP_FL_INDEX_MAX)

#define NOD_MMHEAP_BLK_HEADER_OVERHEAD    (sizeof(size_t))
#define NOD_MMHEAP_BLK_START_OFFSET       (OFFSET_OF_FIELD(nod_mmheap_blk_t, size) + sizeof(size_t))

#define NOD_MMHEAP_POOL_MAX               3

/**
 * memory heap control
 */
typedef struct nod_mmheap_control_st {
    int             pool_cnt;
    void           *pool_start[NOD_MMHEAP_POOL_MAX];

    nod_mmheap_blk_t    block_null; /**< Empty lists point at this block to indicate they are free. */

    uint32_t        fl_bitmap; /**< Bitmaps for free lists. */
    uint32_t        sl_bitmap[NOD_MMHEAP_FL_INDEX_COUNT];

    nod_mmheap_blk_t   *blocks[NOD_MMHEAP_FL_INDEX_COUNT][NOD_MMHEAP_SL_INDEX_COUNT]; /**< Head of free lists. */
} nod_mmheap_ctl_t;

/**
 * @brief Add a pool.
 * Add addtional pool to the heap.
 *
 * @attention None
 *
 * @param[in]   pool_start  start address of the pool.
 * @param[in]   pool_size   size of the pool.
 *
 * @return  errcode
 * @retval  #NOD_MMHEAP_INVALID_POOL_ADDR     start address of the pool is invalid.
 * @retval  #NOD_MMHEAP_INVALID_POOL_SIZE     size of the pool is invalid.
 * @retval  #NOD_MMHEAP_POOL_OVERFLOW         too many pools are added.
 * @retval  #NOD_MMHEAP_POOL_ALREADY_EXIST    the pool is already exist.
 * @retval  #NOD_MMHEAP_NONE                         return successfully.
 */
int nod_mmheap_pool_add(void *pool_start, size_t pool_size);

/**
 * @brief Remove a pool.
 * Remove a pool from the heap.
 *
 * @attention None
 *
 * @param[in]   pool_start  start address of the pool.
 *
 * @return  errcode
 * @retval  #NOD_OBJ_PTR_NULL             start address of the pool is NULL
 * @retval  #NOD_NOD_MMHEAP_POOL_NOT_EXIST    the pool is not exist
 * @retval  #NOD_NONE                     return successfully.
 */
int nod_mmheap_pool_rmv(void *pool_start);

/**
 * @brief Alloc memory.
 * Allocate size bytes and returns a pointer to the allocated memory.
 *
 * @attention size should no bigger than NOD_MMHEAP_BLK_SIZE_MAX.
 *
 * @param[in]   size    size of the memory.
 *
 * @return  the pointer to the allocated memory.
 */
void   *nod_mmheap_alloc(size_t size);

void   *nod_mmheap_calloc(size_t num, size_t size);

/**
 * @brief Alloc start address aligned memory from the heap.
 * Alloc aligned address and specified size memory from the heap.
 *
 * @attention
 *
 * @param[in]   size    size of the memory.
 * @param[in]   align   address align mask of the memory.
 *
 * @return  the pointer to the allocated memory.
 */
void   *nod_mmheap_aligned_alloc(size_t size, size_t align);

/**
 * @brief Realloc memory from the heap.
 * Change the size of the memory block pointed to by ptr to size bytes.
 *
 * @attention
 * <ul>
 * <li> if ptr is K_NULL, then the call is equivalent to nod_mmheap_alloc(size), for all values of size.
 * <li> if ptr is if size is equal to zero, and ptr is not K_NULL, then the call is equivalent to nod_mmheap_free(ptr).
 * </ul>
 *
 * @param[in]   ptr     old pointer to the memory space.
 * @param[in]   size    new size of the memory space.
 *
 * @return  the new pointer to the allocated memory.
 */
void   *nod_mmheap_realloc(void *ptr, size_t size);

/**
 * @brief Free the memory.
 * Free the memory space pointed to by ptr, which must have been returned by a previous call to nod_mmheap_alloc(), nod_mmheap_aligned_alloc(), or nod_mmheap_realloc().
 *
 * @attention
 *
 * @param[in]   ptr     pointer to the memory.
 *
 * @return  None.
 */
void    nod_mmheap_free(void *ptr);

/**
 * @brief Check the pool.
 *
 * @attention
 *
 * @param[in]   pool_start  start address of the pool.
 * @param[out]  info        pointer to the information struct.
 *
 * @return  errcode.
 */
int nod_mmheap_pool_check(void *pool_start, nod_mmheap_info_t *info);

/**
 * @brief Check the heap.
 *
 * @attention
 *
 * @param[out]  info        pointer to the information struct.
 *
 * @return  errcode.
 */
int nod_mmheap_check(nod_mmheap_info_t *info);

int nod_mmheap_init(void *pool_start, size_t pool_size);


#endif //NOD_MMHEAP_H_