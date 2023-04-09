/*
 * mm-naive.c - The fastest, least memory-efficient malloc package.
 * 
 * In this naive approach, a block is allocated by simply incrementing
 * the brk pointer.  A block is pure payload. There are no headers or
 * footers.  Blocks are never coalesced or reused. Realloc is
 * implemented directly using mm_malloc and mm_free.
 *
 * NOTE TO STUDENTS: Replace this header comment with your own header
 * comment that gives a high level description of your solution.
 */
#include <stdio.h>
#include <stdlib.h>
#include <assert.h>
#include <unistd.h>
#include <string.h>

#include "mm.h"
#include "memlib.h"

/*********************************************************
 * NOTE TO STUDENTS: Before you do anything else, please
 * provide your team information in the following struct.
 ********************************************************/
team_t team = {
    /* Team name */
    "ateam",
    /* First member's full name */
    "Harry Bovik",
    /* First member's email address */
    "bovik@cs.cmu.edu",
    /* Second member's full name (leave blank if none) */
    "",
    /* Second member's email address (leave blank if none) */
    ""
};

#define WSIZE 4
#define DSIZE 8
#define CHUNKSIZE (1 << 12)

#define MAX(x, y) ((x) > (y) ? (x) : (y))

#define PACK(size, alloc) ((size | alloc))

#define GET(p) (*(unsigned int *)(p))
#define PUT(p, val) (*(unsigned int *)(p) = (val))

#define GET_SIZE(p) (GET(p) & ~0x7)
#define GET_ALLOC(p) (GET(p) & 0x1)

#define HDRP(bp) ((char *)(bp - WSIZE))
#define FTRP(bp) ((char *)(bp + GET_SIZE(HDRP(bp)) - DSIZE))

#define NEXT_BLKP(bp) ((char *)(bp) + GET_SIZE(((char *)(bp) - WSIZE)))
#define PREV_BLKP(bp) ((char *)(bp) - GET_SIZE(((char *)(bp) - DSIZE)))

#define PRED_LINK(bp) (*(char **)(bp))                           // predecessor 포인터 위치
#define SUCC_LINK(bp) (*(char **)(bp + WSIZE))                    // successor 포인터 위치

static void *extend_heap(size_t words);
static void *coalesce(void *bp);
static void *find_fit(size_t asize);
static void place(void *bp, size_t asize);
static void add_free_block(void *bp);
static void remove_free_block(void *bp);

static char* heap_listp;                                        // heap의 첫번째 포인터
static char* free_listp;
/* 
 * mm_init - initialize the malloc package.
 */
int mm_init(void)
{   
    if ((heap_listp = mem_sbrk(6*WSIZE)) == (void *) - 1)
        return -1;

    PUT(heap_listp, 0);                                         // heap의 첫 패딩 - free(0) 값 넣어준다
    PUT(heap_listp + (1*WSIZE), PACK(DSIZE * 2, 1));            // heap의 Prolog 헤더
    PUT(heap_listp + (2*WSIZE), (int)NULL);                     // predcessor
    PUT(heap_listp + (3*WSIZE), (int)NULL) ;                    // sucessor
    PUT(heap_listp + (4*WSIZE), PACK(DSIZE * 2, 1));            // heap의 Prolog 푸터
    PUT(heap_listp + (5*WSIZE), PACK(0, 1));                    // heap의 Epilog
    
    free_listp = heap_listp + DSIZE;                            // free_listp가 predcessor를 가리킨다

    if (extend_heap(CHUNKSIZE/WSIZE) == NULL)
        return -1;
    return 0;
}

static void *extend_heap(size_t words) {
    char *bp;
    size_t size;

    size = (words % 2) ? (words + 1) * WSIZE : words * WSIZE;   // double word allignment를 고려하여 짝수 개만큼의 size를 반환한다
    if ((long)(bp = mem_sbrk(size)) == -1)
        return NULL;
    
    PUT(HDRP(bp), PACK(size, 0));
    PUT(FTRP(bp), PACK(size, 0));
    PUT(HDRP(NEXT_BLKP(bp)), PACK(0, 1));

    return coalesce(bp);
}

// 가장 앞에 free 함수를 추가 한다
// 새로운 가용 블록을 리스트의 제일 앞에 추가한다
// 새로운 블록의 successor 포인터가 현재 head가 가리키는 블록을 가리키고, 
// head가 새로운 블록을 가리키도록 업데이트 한다
static void add_free_block(void *bp) {
  SUCC_LINK(bp) = free_listp;
  PRED_LINK(free_listp) = bp;
  PRED_LINK(bp) = NULL;
  free_listp = bp;
}

static void remove_free_block(void *bp) {
    // 맨 앞 블록을 삭제하는 경우
  if (free_listp == bp) {
    PRED_LINK(SUCC_LINK(bp)) = NULL;
    free_listp = SUCC_LINK(bp);
  }
  // 중간 블록을 삭제하는 경우
  else {
    SUCC_LINK(PRED_LINK(bp)) = SUCC_LINK(bp);
    PRED_LINK(SUCC_LINK(bp)) = PRED_LINK(bp);
  }
}
/* 
 * mm_malloc - Allocate a block by incrementing the brk pointer.
 *     Always allocate a block whose size is a multiple of the alignment.
 */
void *mm_malloc(size_t size)
{
    size_t asize;                               // 생성할 size
	size_t extendsize;												  // chunksize를 넘길 경우
	char* bp;

	if (size == 0)														 // 만약 입력받은 사이즈가 0 이면 무시
		return NULL;

	if (size <= DSIZE)													 // 만약 입력받은 사이즈가 dsize보다 작아도 최소 size인 16으로 생성
		asize = 2 * DSIZE;
	else
		asize = DSIZE * ((size + (DSIZE) + (DSIZE - 1)) / DSIZE);		     // 8의 배수(Dsize)로 생성

    /* free list 탐색하기 */
	if ((bp = find_fit(asize)) != NULL) {								 // 들어갈 free 블록이 있다면 해당 위치에 넣어준다
		place(bp, asize);
		return bp;
	}

    /* 들어갈 수 있는 fit 존재하지 않을 경우, 추가 메모리를 할당 받고 해당 위치에 넣는다*/
	extendsize = MAX(asize, CHUNKSIZE);
	if ((bp = extend_heap(extendsize / WSIZE)) == NULL)
		return NULL;
	place(bp, asize);
	return bp;
}

/*
 * freelist만을 탐색한다
 */
static void *find_fit(size_t asize) {
    void *bp;

    // header block을 만날 때까지 for문 탐색
    for (bp = free_listp; GET_ALLOC(HDRP(bp)) != 1; bp = SUCC_LINK(bp)) {
        if (GET_SIZE(HDRP(bp)) >= asize)
            return bp;
    }
    return NULL;
}

static void place(void *bp, size_t asize) {
    size_t current_size = GET_SIZE(HDRP(bp));
    remove_free_block(bp);

    // 최소블럭크기 미만의 오차로 딱 맞다면 - 그냥 헤더, 푸터만 갱신해주면 됨
    if ((current_size - asize) < 2*DSIZE ) {
        PUT(HDRP(bp), PACK(current_size, 1));
        PUT(FTRP(bp), PACK(current_size, 1));
    }
    // 넣고도 최소블럭크기 이상으로 남으면 - 헤더는 업데이트, 남은 블록 별도로 헤더, 푸터 처리
    else {
        PUT(HDRP(bp), PACK(asize, 1));
        PUT(FTRP(bp), PACK(asize, 1));
        bp = NEXT_BLKP(bp);
        PUT(HDRP(bp), PACK(current_size - asize, 0));
        PUT(FTRP(bp), PACK(current_size - asize, 0));
        add_free_block(bp);
    }
}

/*
 * mm_free - Freeing a block does nothing.
 */
void mm_free(void *bp) {
    size_t size = GET_SIZE(HDRP(bp));

    PUT(HDRP(bp), PACK(size, 0));
    PUT(FTRP(bp), PACK(size, 0));
    coalesce(bp);
}

/*
 * coalesce
 */
static void *coalesce(void *bp) {
    size_t prev_alloc = GET_ALLOC(FTRP(PREV_BLKP(bp)));         // 이전 footer로부터 할당 정보를 가져온다         
    size_t next_alloc = GET_ALLOC(HDRP(NEXT_BLKP(bp)));         // 다음 header로부터 할당 정보를 가져온다
    size_t size = GET_SIZE(HDRP(bp));                           // 현 사이즈 정보

    if (prev_alloc && next_alloc) {                             // 1. 앞 뒤 모두 할당 상태
        add_free_block(bp);
        return bp;
    }
    else if (prev_alloc && !next_alloc) {                       // 2. 앞 할당 뒤 가용 상태
        remove_free_block(NEXT_BLKP(bp));                       // free list에서 뒤 블럭을 삭제
        size += GET_SIZE(HDRP(NEXT_BLKP(bp)));                  // 뒤 가용 상태의 블록 size와 합친다
        PUT(HDRP(bp), PACK(size, 0));                           // 헤더, 푸터 수정
        PUT(FTRP(bp), PACK(size, 0));
        add_free_block(bp);                                     // free list에 통합한 신규 블럭 추가
    }
    else if (!prev_alloc && next_alloc) {                       // 3. 앞 가용 뒤 할당 상태
        remove_free_block(PREV_BLKP(bp));                       // free list에서 앞 블럭을 삭제
        size += GET_SIZE(HDRP(PREV_BLKP(bp)));                  // 앞 가용 상태의 블럭 size와 합친다
        PUT(HDRP(PREV_BLKP(bp)), PACK(size, 0));    
        PUT(FTRP(bp), PACK(size, 0));
        bp = PREV_BLKP(bp);
		add_free_block(bp);
    }
    else {                                                      // 4. 앞 뒤 모두 가용 상태
        remove_free_block(NEXT_BLKP(bp));
        remove_free_block(PREV_BLKP(bp));
        size += GET_SIZE(HDRP(PREV_BLKP(bp))) + GET_SIZE(FTRP(NEXT_BLKP(bp)));
		PUT(HDRP(PREV_BLKP(bp)), PACK(size, 0));
		PUT(FTRP(NEXT_BLKP(bp)), PACK(size, 0));
        bp = PREV_BLKP(bp);
        add_free_block(bp);
    } 
    return bp;
}

/*
 * mm_realloc - Implemented simply in terms of mm_malloc and mm_free
 */
void *mm_realloc(void *bp, size_t size)
{
    void* old_bp = bp;
	void* new_bp;
	size_t copySize;

	new_bp = mm_malloc(size);											  // 다른데다가 다시 할당 받기

	if (new_bp == NULL)													  // 실패하면 NULL 리턴
		return NULL;

	copySize = GET_SIZE(HDRP(old_bp));									  // 원래 블록의 사이즈
	if (size < copySize)												  // 요청한 사이즈가 작다면 작은사이즈로 카피
		copySize = size;
	memcpy(new_bp, old_bp, copySize);
	mm_free(old_bp);													  // 기존 사이즈는 삭제
	return new_bp;
}














