#include "kernel/param.h"
#include "kernel/types.h"
#include "kernel/stat.h"
#include "user/user.h"
#include "kernel/fs.h"
#include "kernel/fcntl.h"
#include "kernel/syscall.h"
#include "kernel/memlayout.h"
#include "kernel/riscv.h"

#define PAGES 2
#define PGSIZE 4096
#define LENGTH (PGSIZE * PAGES)

void test(const char *msg, int result){
	if(result == -1){
		printf("PASS - %s\n", msg);
	} else {
		printf("FAIL - %s -> result: %d\n", msg, result);
	}
}

int main()
{
  printf("=== TEST START ===\n");

  int before = freemem();
  printf("====== TEST1 - before mmap, freemem: %d\n", before);

  int fd = open("test.txt", O_RDWR | O_CREATE);
  if(fd < 0){
	  printf("open failed\n");
	  exit(1);
  }

  // mmap() : lazy alloc + file mapping
  uint64 lazy_addr = mmap(0, LENGTH, PROT_READ | PROT_WRITE, 0, fd, 0);
  if(lazy_addr == -1){
	  printf("lazy mmap failed\n");
	  close(fd);
	  exit(1);
  }
  printf("====== TEST2 - lazy-mmap succeeded at address %ld, freemem: %d (same as %d) ======\n", lazy_addr, freemem(), before);

  // access addr to lazy alloc
  char *lp = (char *)lazy_addr;
  for (int i = 0; i < LENGTH; i++)
    lp[i] = 'X';
  printf("====== TEST3 - access and write data & page fault, freemem: %d  ======\n", freemem());

  // mmap() : populate + anonymous
  uint64 anon_addr = mmap(LENGTH, LENGTH, PROT_READ | PROT_WRITE, MAP_ANONYMOUS | MAP_POPULATE, -1, 0);
  if(anon_addr == -1){
	  printf("anon mmap failed\n");
	  exit(1);
  } 
  printf("====== TEST4 - anon-mapp succeded at address %ld, freemem: %d ======\n", anon_addr, freemem());

  int sum = 0;
  char *ap = (char *)anon_addr;
  for (int i = 0; i < LENGTH; i++) {
    sum += ap[i]; // read
  }
  printf("====== TEST5 - read anon data, thus sum has to be 0: sum = %d ======\n", sum);

  int after = freemem();
  printf("====== TEST6 - free pages after write (after page faults): %d ======\n", after);

  // munmap test
  if(munmap(lazy_addr) == -1){
	  printf("munmap lazy_addr failed\n");
	  exit(1);
  }
  if(munmap(anon_addr) == -1){
	  printf("munmap-anon_addr failed\n");
	  exit(1);
  }
  int after_unmap = freemem();
  printf("====== TEST7 - after munmap(), fremmem = %d ======\n", after_unmap);

  close(fd);
  unlink("test.txt");
  printf("=== TEST COMPLETE ===\n");
 
	printf("\n=== Faiuler case TEST ===\n");
	printf("=== TEST START ===\n");
	// uint64 mmap(uint64 addr, int length, int prot, int flags, int fd, int offset
	// mmap parameter test
	test("mmap - invalid addr",
			mmap(123, LENGTH, PROT_READ | PROT_WRITE, 0, fd, 0));
	test("mmap - invalid length",
			mmap(0, 123, PROT_READ | PROT_WRITE, 0, fd, 0));
	test("mmap - not anonymous but fd == -1",
			mmap(0, LENGTH, PROT_READ, 0, -1, 0));
	test("mmap - anonymous but fd != -1",
			mmap(0, LENGTH, PROT_READ, MAP_ANONYMOUS, fd, 0));
	test("mmap - anonymous but offset != 0",
			mmap(0, LENGTH, PROT_READ, MAP_ANONYMOUS, -1, 123));
	// permission
	// read only
	int fd_readonly = open("readonly.txt", O_RDONLY | O_CREATE);
	if(fd_readonly < 0){
		printf("fd_readonly open failed\n");
		exit(1);
	}
	test("mmap - PROT_WRITE but no permission",
			mmap(0, LENGTH, PROT_WRITE, 0, fd_readonly, 0));
	// write
	close(fd_readonly);
	int fd_write = open("testfile2.txt", O_WRONLY | O_CREATE);
  	if (fd_write < 0) {
    		printf("open testfile2.txt failed\n");
    		exit(1);
  	}
  	test("mmap: PROT_READ but file is write-only",
       			mmap(0, LENGTH, PROT_READ, 0, fd_write, 0));
	close(fd_write);
	// read and write
	uint64 result_mmap;
  	int fd_rw = open("testfile3.txt", O_RDWR | O_CREATE);
  	if (fd_rw < 0) {
    		printf("open testfile3.txt failed\n");
    		exit(1);
  	}
	test("mmap: PROT_READ | PROT_WRTIE and must be [FAIL]",
			result_mmap = mmap(0, LENGTH, PROT_READ | PROT_WRITE, 0, fd_rw, 0));
	munmap(result_mmap);
  	close(fd_rw);


/*	mmap(0, LENGTH, PROT_READ, MAP_ANONYMOUS | MAP_POPULATE, -1, 0);
	test("mmap - double mmap",
			mmap(0, LENGTH, PROT_READ, MAP_ANONYMOUS | MAP_POPULATE, 0, 0));
	munmap(0);*/ 
	// painc! (PASS)

	// unmap parameter test
	uint64 test_addr = mmap(0, LENGTH, PROT_READ, MAP_ANONYMOUS | MAP_POPULATE, fd, 0);
	test("munmap - unmmaped adderss",
			munmap(test_addr+1234));
	test("munmap - double unmapped",
			munmap(lazy_addr));

	/* fork test */
	int fork_fd = open("testfile.txt", O_RDWR | O_CREATE);
  	if (fork_fd < 0) {
    		printf("open failed\n");
    		exit(1);
  	}

	  // write known content
  	write(fork_fd, "HELLO_FORK\0", 11);
  	close(fork_fd);

  	// reopen for mmap
  	fork_fd = open("testfile.txt", O_RDWR);
  	if (fork_fd < 0) {
    		printf("open failed\n");
    		exit(1);
 	}

	uint64 fork_addr = mmap(0, LENGTH, PROT_READ | PROT_WRITE, 0, fork_fd, 0);
	char *str_addr = (char *)fork_addr;
  	if (fork_addr == -1) {
    		printf("mmap failed\n");
    		close(fork_fd);
    		exit(1);
  	}

	
  int pid = fork();
  if (pid == 0) {
    // child process
    printf("child mmap: %s\n", str_addr);  // Expect: HELLO_FORK
    str_addr[0] = 'C';  // child modifies memory
    printf("child changed mmap: %s\n", str_addr); // Expect: CELLO_FORK
    munmap(fork_addr);
    close(fork_fd);
    exit(0);
  } else {
    wait(0);
    // parent should still see original data
    printf("parent after child: %s\n", str_addr); // Depending on sharing: HELLO_FORK or CELLO_FORK
    munmap(fork_addr);
    close(fork_fd);
  }


	// mmap_area_max per process test
	//printf("=== freelist OOM TEST ===\n");
	printf("=== mmap_area_max TEST ===\n");
	printf("====== TEST - before mmap, freemem : %d ======\n", freemem());
	int cnt = 0;
	static uint64 addrs[100];
	uint64 va = 0;
	while(cnt < 100) {
		uint64 p = mmap(va, PGSIZE, PROT_READ | PROT_WRITE, MAP_ANONYMOUS | MAP_POPULATE, -1, 0);
		printf("====== TEST - count = %d, free page num in while() : %d, and addr is %ld ======\n", cnt, freemem(), p);
		if(p == -1){
			printf("mmap failed in %d\n", cnt);
			break; // maybe, 64(->MMAP_AREA_MAX) or less then 64 (->freelist out) 
		}
		else{
			va += PGSIZE;
			addrs[cnt++] = p;
		}
	}

	printf("====== TEST1 - after infinite allocation, freemem : %d, count = %d ======\n", freemem(), cnt);

	for(int i=0; i<cnt; i++){
		if(addrs[i] != -1){
			printf("====== TEST - unmapped page count = %d and addr is %ld ======\n", i, addrs[i]);
			munmap(addrs[i]);
		}
	}
	printf("====== TEST2 - after free, freemem : %d ======\n", freemem());	
	

	printf("=== ALL TEST COMPLETE ===\n");
  exit(0);
}
