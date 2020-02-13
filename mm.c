#include <assert.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include "./memlib.h"
#include "./mm.h"
#include "./mminline.h"

// Max macro used across methods
#define max(a, b)(a > b? a : b)

// prologue and epilogue block global variables
// these act as 'dummy' blocks to help eliminate edge cases,
// like coalescing beyond the bounds of the heap and iterating over your heap.
block_t* prologue;
block_t* epilogue;

// rounds up to the nearest multiple of WORD_SIZE
static inline size_t align(size_t size) {
    return (((size) + (WORD_SIZE - 1)) & ~(WORD_SIZE - 1));
}

int mm_check_heap(void);

/*
 *                             _       _ _
 *     _ __ ___  _ __ ___     (_)_ __ (_) |_
 *    | '_ ` _ \| '_ ` _ \    | | '_ \| | __|
 *    | | | | | | | | | | |   | | | | | | |_
 *    |_| |_| |_|_| |_| |_|___|_|_| |_|_|\__|
 *                       |_____|
 *
 * initializes the dynamic storage allocator (allocate initial heap space)
 * arguments: none
 * returns: 0, if successful
 *         -1, if an error occurs
 */
int mm_init(void) {
	// global variable initialized in mminline.h. Set NULL for each new init.
    flist_first = NULL;

	// prologue block init.
	prologue = (block_t*) mem_sbrk(MINBLOCKSIZE);
	if (prologue == (void*) -1){
		perror("Prologue Block Initialization Failure\n");
		return -1;
	}
    block_set_size_and_allocated(prologue, TAGS_SIZE, 1);
	
	// epilogue block init.
	epilogue = block_next(prologue);
	block_set_size_and_allocated(epilogue, TAGS_SIZE, 1);
	return 0;
}

/*     _ __ ___  _ __ ___      _ __ ___   __ _| | | ___   ___
 *    | '_ ` _ \| '_ ` _ \    | '_ ` _ \ / _` | | |/ _ \ / __|
 *    | | | | | | | | | | |   | | | | | | (_| | | | (_) | (__
 *    |_| |_| |_|_| |_| |_|___|_| |_| |_|\__,_|_|_|\___/ \___|
 *                       |_____|
 *
 * allocates a block of memory and returns a pointer to that block's payload
 * arguments: size: the desired payload size for the block
 * returns: a pointer to the newly-allocated block's payload (whose size
 *          is a multiple of ALIGNMENT), or NULL if an error occurred
 */
void *mm_malloc(size_t size) {
    if ((int) size < 0){
		return NULL;
	}
    block_t* first = flist_first;
	if (size < MINBLOCKSIZE){
		size = MINBLOCKSIZE;
	}
    size = align(size);
	size_t block_size_req = size + TAGS_SIZE;
	block_t* curr = flist_first;
    size_t max = max(block_size_req, 1024);
	if (curr == NULL){
        assert((int) max >= 0);
        if (max < MINBLOCKSIZE){
            max = MINBLOCKSIZE;
        }
        max = align(max);
        block_t* ext;
        if ((ext = (block_t*) mem_sbrk(max)) == (void*) -1){
            perror("error message to edit\n");
            return (block_t*) -1;
        }
        ext = epilogue;
        block_set_size_and_allocated(ext, max, 0);
        insert_free_block(ext);
        epilogue = block_next(ext);
	    block_set_size_and_allocated(epilogue, TAGS_SIZE, 1);
		if ((curr = ext) == (void*) -1){
			perror("error message to edit\n");
			return NULL;
		}
	} else {
        while (block_size(curr) < block_size_req){
			curr = block_next_free(curr);
			if (curr == first){
                assert((int) max >= 0);
                if (max < MINBLOCKSIZE){
                    max = MINBLOCKSIZE;
                }
                max = align(max);
                block_t* ext;
                if ((ext = (block_t*) mem_sbrk(max)) == (void*) -1){
                    perror("error message to edit\n");
                    return (block_t*) -1;
                }
                ext = epilogue;
                block_set_size_and_allocated(ext, max, 0);
                insert_free_block(ext);
                epilogue = block_next(ext);
                block_set_size_and_allocated(epilogue, TAGS_SIZE, 1);
                if ((curr = ext) == (void*) -1){
					perror("error message to edit\n");
					return NULL;
				}
			}
		}
	}
    if (block_size(curr) - block_size_req >= 8 * MINBLOCKSIZE){
		size_t block_size_init = block_size(curr);
        pull_free_block(curr);
        block_set_size_and_allocated(curr, block_size_req, 1);
        block_t* new_free_block = block_next(curr);
        block_set_size_and_allocated(new_free_block, block_size_init - block_size_req, 0);
        insert_free_block(new_free_block);
	} else {
        pull_free_block(curr);
		block_set_allocated(curr, 1);
	}
	return curr->payload;
}

/*                              __
 *     _ __ ___  _ __ ___      / _|_ __ ___  ___
 *    | '_ ` _ \| '_ ` _ \    | |_| '__/ _ \/ _ \
 *    | | | | | | | | | | |   |  _| | |  __/  __/
 *    |_| |_| |_|_| |_| |_|___|_| |_|  \___|\___|
 *                       |_____|
 *
 * frees a block of memory, enabling it to be reused later
 * arguments: ptr: pointer to the block's payload
 * returns: nothing
 */
void mm_free(void *ptr) {
	// get the block from the pointer and check if it is 'freeable'.
	// should not be free if ptr is NULL, invalid, or points to an already freed block.
    block_t* block = payload_to_block(ptr);
    assert(block_allocated(block));
	// free
	block_set_allocated(block, 0);
	insert_free_block(block);
	// edge case: 
    block_t* next = block_next(block);
	block_t* prev = block_prev(block);
	pull_free_block(block);	
    if (!block_allocated(next)){
		pull_free_block(next);
		block_set_size(block, block_size(block) + block_size(next));
	}	
    if (!block_allocated(prev)){
		pull_free_block(prev);
		block_set_size(prev, block_size(prev) + block_size(block));
		block = prev;
	}
    insert_free_block(block);
}

/*
 *                                            _ _
 *     _ __ ___  _ __ ___      _ __ ___  __ _| | | ___   ___
 *    | '_ ` _ \| '_ ` _ \    | '__/ _ \/ _` | | |/ _ \ / __|
 *    | | | | | | | | | | |   | | |  __/ (_| | | | (_) | (__
 *    |_| |_| |_|_| |_| |_|___|_|  \___|\__,_|_|_|\___/ \___|
 *                       |_____|
 *
 * reallocates a memory block to update it with a new given size
 * arguments: ptr: a pointer to the memory block's payload
 *            size: the desired new payload size
 * returns: a pointer to the new memory block's payload
 */
void *mm_realloc(void *ptr, size_t size) {
    if ((int) size < 0){
		return NULL;
	}
	if (ptr == NULL){
		if (!size){
			return NULL;
		}
        if (mm_malloc(size) == NULL){
			perror("error message to edit\n");
			return NULL;
		}
	}
    if (!size){
        mm_free(ptr);
		return NULL;			
	}
    size = align(size);
	size += TAGS_SIZE;
	block_t* block = payload_to_block(ptr);
	size_t original_size = block_size(block);
    if (original_size >= size){
		return block->payload;
	} else {
        size_t cpy_size;
		block_t* next = block_next(block);
        cpy_size = original_size - TAGS_SIZE;
		if (!block_allocated(next)){
			pull_free_block(next);
			block_set_size_and_allocated(block, block_size(block) + block_size(next), 1);
			original_size = block_size(block);
			if (size <= original_size){
				return block->payload;
			}
		}
        if (original_size < size){
			block_t* prev = block_prev(block);
			if (!block_allocated(prev)){
				pull_free_block(prev);
				block_set_size_and_allocated(prev, block_size(block) + block_size(prev), 1);
				block = prev;
				original_size = block_size(block);
				if (size <= original_size){
                    memmove(block->payload, ptr, cpy_size);
					return block->payload;
				}
				ptr = block->payload;
			}
		}
        block_t* payload;
		if ((payload = mm_malloc(size)) == NULL){
			perror("error message to edit\n");
			return NULL;
		}
		block_t* new_block = payload_to_block(payload);
        memcpy(new_block->payload, ptr, cpy_size);
        mm_free(ptr);
		return new_block->payload;
    }
    return block->payload;
}

/*
 * checks the state of the heap for internal consistency and prints informative
 * error messages
 * arguments: none
 * returns: 0, if successful
 *          nonzero, if the heap is not consistent
 */
int mm_check_heap(void) {
    block_t* curr = flist_first;
	if (curr == NULL){
		return 0;
	}
    if (block_allocated(curr)){
		printf("Block address = %p, block size = %d, heap error: %s\n", (void*) curr, (int) block_size(curr), "found an allocated block in the free list!\n");
		exit(1);
	}
	curr = block_next_free(curr);
	while (curr != flist_first){
        if (block_allocated(curr)){
			printf("Block address = %p, block size = %d, heap error: %s\n", (void*) curr, (int) block_size(curr), "found an allocated block in the free list!\n");
			exit(1);
		}
        if (block_allocated(block_next_free(curr))){
			printf("Block address = %p, block size = %d, heap error: %s\n", (void*) curr, (int) block_size(curr), "next free block is not free!\n");
			exit(1);
		}
        if (block_allocated(block_prev_free(curr))){
			printf("Block address = %p, block size = %d, heap error: %s\n", (void*) curr, (int) block_size(curr), "next free block is not free!\n");
			exit(1);
		}
        if (!block_allocated(block_next(curr))){
			printf("Block address = %p, block size = %d, heap error: %s\n", (void*) curr, (int) block_size(curr), "has not coalesced with next block!\n");
			exit(1);
		}
		if (!block_allocated(block_prev(curr))){
			printf("Block address = %p, block size = %d, heap error: %s\n", (void*) curr, (int) block_size(curr), "has not coalesced with previous block!\n");
			exit(1);
		}
		curr = block_next_free(curr);
	}
	block_t* heap_lo = mem_heap_lo();
	block_t* heap_hi = mem_heap_hi();
    if ((curr = heap_lo) != prologue){
		printf("prologue address = %p, prologue size = %d, heap error: %s\n", (void*) prologue, (int) block_size(prologue), "prologue is not the first block in the heap!\n");
		exit(1);
	}
	if ((void*) ((long) heap_hi - (long)(TAGS_SIZE - 1)) != epilogue){
		printf("epilogue address = %p, epilogue size = %d, heap error: %s\n", (void*) epilogue, (int) block_size(epilogue), "epilogue is not the last block in the heap!\n");
		exit(1);
	}
	while (curr != epilogue){
        if (curr < heap_lo || curr > heap_hi){
			printf("Block address = %p, block size = %d, heap error: %s\n", (void*) curr, (int) block_size(curr), "block out of heap's bounds!\n");
			exit(1);
		}
        if (block_size(curr) != block_end_size(curr) || block_allocated(curr) != block_end_allocated(curr)){
			printf("Block address = %p, block size = %d, heap error: %s\n", (void*) curr, (int) block_size(curr), "header and footer of block do not match!\n");
			exit(1);
		}
		curr = block_next(curr);
	}
    if (epilogue < heap_lo || epilogue > heap_hi){
			printf("Block address = %p, block size = %d, heap error: %s\n", (void*) curr, (int) block_size(curr), "block out of heap's bounds!\n");
			exit(1);
	}
    return 0;
}
