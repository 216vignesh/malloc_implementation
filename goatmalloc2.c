#include<unistd.h>
#include "goatmalloc.h"
#include<stdio.h>
#include<errno.h>
#include<sys/mman.h>
#include<stddef.h>


#define ALIGN 8
static void *arena_st;
static size_t arena_size;
static node_t *free_list;
int statusno=ERR_UNINITIALIZED;
int init(size_t size)
{
    if(size==-1)
    {
        return ERR_BAD_ARGUMENTS;
    }
    size_t page=(size_t)getpagesize();
    size_t adjusted=(size+page-1) & ~(page-1);
    
}