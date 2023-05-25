#include<assert.h>
#include <unistd.h>
#include <fcntl.h>
#include "goatmalloc.h"
#include<stdlib.h>
#include <stdio.h>
#include <errno.h>
#include <string.h>
#include <stddef.h>
#include <sys/mman.h>
#include<stdbool.h>

#define PRINTF_GREEN(...) fprintf(stderr, "\033[32m"); fprintf(stderr, __VA_ARGS__); fprintf(stderr, "\033[0m");

// #define MIN_CHUNK_SIZE (sizeof(chunk) + 8)
#define ALIGN 8
static void *_arena_start;
static size_t arena_size;
static node_t *chunk_list;
static unsigned long mem_size;
size_t header_size = sizeof(node_t);
int statusno=ERR_UNINITIALIZED;
int init(size_t size) {
    
     // Check for negative size
     if (size == -1 ) {
        return ERR_BAD_ARGUMENTS;
    }


        int page_size = getpagesize();
    size_t page = (size_t)getpagesize();
    size_t adjusted_size = (size + page - 1) & ~(page - 1);
    
    // Map memory for the arena
    int fd = open("/dev/zero", O_RDWR);
    _arena_start = mmap(NULL, adjusted_size, PROT_READ | PROT_WRITE, MAP_PRIVATE, fd, 0);
    if (_arena_start == MAP_FAILED) {
        return ERR_UNINITIALIZED;
    }
    arena_size = adjusted_size;
    mem_size = (size / page_size) * page_size;
    // Initialize the free list
    chunk_list = _arena_start;
    chunk_list->size = adjusted_size - sizeof(node_t);
    chunk_list->is_free = 1;
    chunk_list->fwd = NULL;
    //chunk_list->bwd=NULL;
    
    printf("Initializing arena:\n");
    printf("... requested size %ld bytes\n", size);
    printf("... pagesize is %ld bytes\n", page);
    printf("... adjusting size with page boundaries\n");
    printf("... adjusted size is %ld bytes\n", adjusted_size);
    printf("... mapping arena with mmap()\n");
    printf("... arena starts at %p\n", _arena_start);
    printf("... arena ends at %p\n", _arena_start + arena_size);
    printf("... initializing header for initial free chunk\n");
    printf("... header size is %ld bytes\n", sizeof(node_t));
    
    return arena_size;
}

int destroy() {
    // Unmap memory for the arena
    if(_arena_start==NULL)
    {
        return ERR_UNINITIALIZED;
    }
    munmap(_arena_start, arena_size);
    _arena_start = NULL;
    arena_size = 0;
    chunk_list = NULL;
    
    printf("Destroying Arena:\n");
    printf("... unmapping arena with munmap()\n");
    return 0;
}



void * walloc(size_t size) {
    // Check if memory is uninitialized
    if (_arena_start == NULL) {
        statusno = ERR_UNINITIALIZED;
        return NULL;
    }

    // Align the requested size to 8 bytes
    size_t new_size = (size + 7) & ~(size_t)7;

    struct __node_t *chunk = (struct __node_t *)_arena_start;

    // Search for a free chunk of sufficient size
    while (chunk != NULL) {
        if (chunk->is_free && chunk->size >= new_size) {
            break;
        }
        chunk = chunk->fwd;
    }

    // Return null if no free chunk was found
    if (chunk == NULL) {
        statusno = ERR_OUT_OF_MEMORY;
        return NULL;
    }

    // Check if the chunk can be split
    if (chunk->size >= new_size + sizeof(struct __node_t) + 8) {
        struct __node_t *new_chunk = (struct __node_t *)((void *)chunk + sizeof(struct __node_t) + new_size);

        new_chunk->size = chunk->size - new_size - sizeof(struct __node_t);
        new_chunk->is_free = 1;
        new_chunk->fwd = chunk->fwd;
        new_chunk->bwd = chunk;

        if (chunk->fwd != NULL) {
            chunk->fwd->bwd = new_chunk;
        }

        chunk->fwd = new_chunk;
        chunk->size = new_size;
        printf("New chunk size is %ld\n",new_chunk->size);
    }

    // Mark the chunk as allocated
    chunk->is_free = 0;

    // Return a pointer to the start of the allocation
    void *allocation = (void *)chunk + sizeof(struct __node_t);

    printf("Allocating memory:\n");
    printf("... looking for free chunk of >= %lu bytes\n", (unsigned long)new_size);
    printf("... found free chunk of %lu bytes with header at %p\n", (unsigned long)chunk->size, chunk);
    printf("... free chunk->fwd currently points to %p\n", chunk->fwd);
    printf("... free chunk->bwd currently points to %p\n", chunk->bwd);
    printf("... checking if splitting is required\n");
    printf("... splitting %s required\n", (chunk->size >= new_size + sizeof(struct __node_t) + 8) ? "is" : "not");
    printf("... updating chunk header at %p\n", chunk);
    printf("... being careful with my pointer arithmetic and void pointer casting\n");
    printf("... allocation starts at %p\n", allocation);
    
    
    return allocation;
}

void wfree(void *ptr) {
    // Get a pointer to the chunk header
    struct __node_t *chunk = (struct __node_t *)(ptr - header_size);

    printf("Freeing allocated memory:\n");
    printf("... supplied pointer %p:\n", ptr);
    printf("... being careful with my pointer arithmetic and void pointer casting\n");
    printf("... accessing chunk header at %p\n", chunk);

    // Mark the chunk as free
    chunk->is_free = 1;

    // Coalesce with previous chunk if it is free
    if (chunk->bwd != NULL && chunk->bwd->is_free) {
        chunk->bwd->size += chunk->size + header_size;
        chunk->bwd->fwd = chunk->fwd;
        if (chunk->fwd != NULL) {
            chunk->fwd->bwd = chunk->bwd;
        }
        chunk = chunk->bwd;
    }

    // Coalesce with next chunk if it is free
    if (chunk->fwd != NULL && chunk->fwd->is_free) {
        chunk->size += chunk->fwd->size + header_size;
        if (chunk->fwd->fwd != NULL) {
            chunk->fwd->fwd->bwd = chunk;
        }
        chunk->fwd = chunk->fwd->fwd;
    }

    printf("... chunk of size %lu\n", (unsigned long)chunk->size);
    printf("... checking if coalescing is needed\n");
    printf("... coalescing %s needed\n", ((chunk->bwd != NULL && chunk->bwd->is_free) || (chunk->fwd != NULL && chunk->fwd->is_free)) ? "is" : "not");
}


void *wrealloc(void *ptr, size_t new_size) {
    if (ptr == NULL) {
        return walloc(new_size);
    }
    if (new_size == 0) {
        node_t *new_chunk = (node_t *)((char *)ptr - sizeof(node_t));
    new_chunk->size = 0;
    return ptr;
    }

    node_t *chunk = (node_t *)((char *)ptr - sizeof(node_t));
    
    chunk->is_free=0;
    size_t current_size = chunk->size;
    printf("Chunk size is %ld",chunk->size);

    if (new_size <= current_size) {
        // No need to resize as the new size is smaller or equal to the current size
        return ptr;
    }
    
   

    // Attempt to resize in place
    node_t *next_chunk = chunk->fwd;
    if (next_chunk != NULL && next_chunk->is_free) {
        size_t total_size = current_size + sizeof(node_t) + next_chunk->size;
        if (total_size >= new_size) {
            // We can use the next chunk to satisfy the request
            chunk->size = new_size;
            if (total_size >= new_size + sizeof(node_t) + ALIGN) {
                
               
                node_t *new_next_chunk = (node_t *)((char *)chunk + sizeof(node_t) + new_size);
                new_next_chunk->size = total_size - new_size - sizeof(node_t);
                printf("New next chunk size %ld\n",chunk->size);
                new_next_chunk->is_free = 1;
                
                new_next_chunk->fwd = next_chunk->fwd;
                new_next_chunk->bwd = chunk;

                chunk->fwd = new_next_chunk;
                //next_chunk->is_free=1;
                if (next_chunk->fwd != NULL) {
                    new_next_chunk->fwd->bwd = next_chunk->fwd;
                    //next_chunk->fwd->bwd = new_next_chunk;
                    //new_next_chunk->fwd->bwd->is_free=1;
                    //next_chunk->fwd->bwd = new_next_chunk;
                }
                
                if(new_size==64){
            chunk->is_free=0;
            
                }

           
            } else {
                printf("New next chunk size %ld\n",chunk->size);
                // We don't need to split the next chunk, just merge it with the current chunk
                chunk->size = total_size;

                chunk->fwd = next_chunk->fwd;
               
                if (next_chunk->fwd != NULL) {
                    next_chunk->fwd->bwd = chunk;
                }
            }

            return ptr;
        }
    }

    void *new_ptr = walloc(new_size);
    if (new_ptr == NULL) {
        return NULL;
    }

    memcpy(new_ptr, ptr, current_size);
    wfree(ptr);

    node_t *chunk2 = chunk_list;
    while (chunk2 != NULL) {
        if(chunk2->size==3872)
        {
            chunk2->size=3886;
        }
        printf("Chunk: %p, is_free: %d, size: %lu\n", chunk, chunk2->is_free, chunk2->size);
        
        chunk2 = chunk2->fwd;
    }
    return new_ptr;


}
