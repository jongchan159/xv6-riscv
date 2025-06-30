#include "types.h"
#include "param.h"
#include "memlayout.h"
#include "riscv.h"
#include "spinlock.h"
#include "proc.h"
#include "defs.h"
#include "sleeplock.h"
#include "fs.h"
#include "file.h"

struct spinlock tickslock;
uint ticks; // total ticks
uint delta_tick; // increment of tick

extern char trampoline[], uservec[], userret[];

// in kernelvec.S, calls kerneltrap().
void kernelvec();

extern int devintr();

int pagefault_handler(uint64 fault_addr, uint64 scause);

// pa2 - when clockintr() & usertrap()
// update process's scheduler value
static void updateschedparam(struct proc *p){
  //printf("\n DEBUG: update sched param... \n");
  int weight = p->weight;
  int tick = delta_tick * 1000;
  if(holding(&p->lock)){
    acquire(&p->lock);
    p->runtime += tick; // increment one tick
    p->vruntime += (tick * 1024) / weight;
    release(&p->lock);
  }
  else{
    p->runtime += tick; // increment one tick
    p->vruntime += (tick * 1024) / weight;
  }
  //ps(p->pid);
  delta_tick = 0;
}

void
trapinit(void)
{
  initlock(&tickslock, "time");
}

// set up to take exceptions and traps while in the kernel.
void
trapinithart(void)
{
  w_stvec((uint64)kernelvec);
}

//
// handle an interrupt, exception, or system call from user space.
// called from trampoline.S
//
void
usertrap(void)
{
  int which_dev = 0;

  if((r_sstatus() & SSTATUS_SPP) != 0)
    panic("usertrap: not from user mode");

  // send interrupts and exceptions to kerneltrap(),
  // since we're now in the kernel.
  w_stvec((uint64)kernelvec);

  if(mycpu()->noff > 1){
    // printf("DEBUG: myproc() in usertrap(), mycpu()->noff: %d\n", mycpu()->noff);
  }
  struct proc *p = myproc();
  
  // save user program counter.
  p->trapframe->epc = r_sepc();

  // pa3 - page fault
  uint64 scause = r_scause(); // 13: page fault, 15: store access fault
  uint64 fault_addr = r_stval(); // address that caused the fault
  
  if(r_scause() == 8){
    // system call

    if(killed(p))
      exit(-1);

    // sepc points to the ecall instruction,
    // but we want to return to the next instruction.
    p->trapframe->epc += 4;

    // an interrupt will change sepc, scause, and sstatus,
    // so enable only now that we're done with those registers.
    intr_on();

    syscall();
  } 
  else if(scause == 13 || scause == 15){
	  // printf("DBG: Before enter PF handler\n");
	  if(pagefault_handler(fault_addr, scause) < 0){
		  p->killed = 1;
	  }
  }
  else if((which_dev = devintr()) != 0){
    // ok
  } else {
    printf("usertrap(): unexpected scause 0x%lx pid=%d\n", r_scause(), p->pid);
    printf("            sepc=0x%lx stval=0x%lx\n", r_sepc(), r_stval());
    setkilled(p);
  }

  if(killed(p))
    exit(-1);

  // give up the CPU if this is a timer interrupt.
  // this is where the delta_tick is incremented used
  if(which_dev == 2){
    // printf("DEBUG: time_interrupt occur, p = %s %d, state = %d\n", p->name, p->pid, p->state);
    // if process is going sleep(chan != 0), no call yield()
    // because alraedy call sched() in sleep()
    if(p->chan == 0 && p && p->state == RUNNING){
      // pa2 - process is running and call clockintr()
      // prevent double sched()
      if (mycpu()->noff > 1 || holding(&p->lock)){ 
        // printf("DEBUG: in usertrap, already in sched()");
        return;
      }

      // // printf("DEBUG: problem in usertrap()\n");
      delta_tick++;
      updateschedparam(p);

      // printf("DEBUG: delta_tick = %d\n", delta_tick);

      if(p->runtime >= p->time_slice){
        //printf("\n=====DEBUG: process time over.=====\n=====update schedparam and yield()===== \n");
	      //schedbit = 1;
        //ps(0);
	      p->vdeadline = p->vruntime + (p->time_slice*1024) / p->weight;
        yield();
      }
    }
  }
  /*
  // pa3 - page fault
  uint64 scause = r_scause(); // 13: page fault, 15: store access fault
  uint64 fault_addr = r_stval(); // address that caused the fault 

  if (scause == 13 || scause == 15) {
    printf("DEBUG: Before enter pagefault handler\n");	  
    if (pagefault_handler(fault_addr, scause) < 0) {
        p->killed = 1;  // 실패하면 프로세스 종료
    }
    return;
  }
  */
  usertrapret();
}

// pa3 - pagefault handler
int pagefault_handler(uint64 fault_addr, uint64 scause)
{
	//printf("DEBUG: Succesfully enter in page fault handler\n");
	//printf("DBG : pagefault: fault_addr = %ld, scause = %ld\n", fault_addr, scause);
	// 1. 프로세스 및 페이지 폴트 발생 주소 확인
  	struct proc *p = myproc();
  	uint64 va = PGROUNDDOWN(fault_addr);
  	struct mmap_area *ma = 0;
  
  	// 2. 페이지 폴트가 발생한 프로세스 가상 주소 찾기
	for (int i = 0; i < MMAP_AREA_MAX; i++) {
	  if (p->mmap_area[i].length == 0)
	    continue; // 비어있으면 건너뜀
	
    	  uint64 start = p->mmap_area[i].addr;
    	  uint64 end = start + p->mmap_area[i].length;
    	  if (va >= start && va < end) {
      		ma = &p->mmap_area[i];
		//printf("DBG: (pagefault handler)ma->addr : %ld\n", ma->addr);
      		break;
    	  }
	}
	
	// ma에 대한 오류 처리
	if(ma == 0){ // 페이지 발견 실패 시 오류
		panic("wrong ma in pagefault handler\n");
		//printf("wrong ma");
		return -1;
	}
	if(ma->flags & MAP_POPULATE){	// 페이지 폴트인데 POPULATE? -> 스왑 영역에 있는 걸수도 있나?
		/*
		LOAD FROM SWAP SPACE
		or
		return -1;	
		*/
	}
	if(scause == 15 && !(ma->prot & PROT_WRITE)){ // 쓰기 권한 없을 시 오류
		printf("no write perm\n");
		return -1;
	}
	
	// 3. 메모리 할당
	char *mem = kalloc();
	if(!mem) {
		printf("kalloc failed\n");
		return -1;
	}
	
	int perm = PTE_U;
  	if(ma->prot & PROT_READ) perm |= PTE_R;
  	if(ma->prot & PROT_WRITE) perm |= PTE_W;
 	//printf("DBG: breakpoint before memset\n"); 
  	// 가상 메모리 기본 0 초기화 (anonymous)
	memset(mem, 0, PGSIZE);
	
	//printf("DBG: breakpoint before mappges\n");
/*
	                // double-mapping 방지
                        pte_t *pte = walk(p->pagetable, va, 0);
                        if (pte && (*pte & PTE_V)) {
                        // 이미 매핑된 페이지
				printf("double mapping\n");
                                kfree(mem);
                                return -1;
                        }
*/
	// 물리 메모리 할당
	if(mappages(p->pagetable, va, PGSIZE, (uint64)mem, perm) < 0){
		//panic("DBG: mappages in pagefault handler");
		kfree(mem);
		return -1;
	}

	//printf("DBG: breakpoint before file mapping\n");	
	// file mapping (!anonymous)
	// ma->offset + (va - ma->addr) -> new offset (mmem_area의 첫번째 페이지가 아닐 수도 있음)
	struct file* f = ma->f;
	if(f) {
			ilock(f->ip);
			readi(f->ip, 0, (uint64)mem, ma->offset + (va - ma->addr), PGSIZE);
			iunlock(f->ip);
	}

	//printf("DBG: breakpoint before return\n");	
	return 0;
}

//
// return to user space
//
void
usertrapret(void)
{
  // // printf("DEBUG: problem in usertrapret()\n");
  if(mycpu()->noff > 1){
    // printf("DEBUG: myproc() in usertrap(), mycpu()->noff: %d\n", mycpu()->noff);
  }
  struct proc *p = myproc();

  // we're about to switch the destination of traps from
  // kerneltrap() to usertrap(), so turn off interrupts until
  // we're back in user space, where usertrap() is correct.
  intr_off();

  // send syscalls, interrupts, and exceptions to uservec in trampoline.S
  uint64 trampoline_uservec = TRAMPOLINE + (uservec - trampoline);
  w_stvec(trampoline_uservec);

  // set up trapframe values that uservec will need when
  // the process next traps into the kernel.
  p->trapframe->kernel_satp = r_satp();         // kernel page table
  p->trapframe->kernel_sp = p->kstack + PGSIZE; // process's kernel stack
  p->trapframe->kernel_trap = (uint64)usertrap;
  p->trapframe->kernel_hartid = r_tp();         // hartid for cpuid()

  // set up the registers that trampoline.S's sret will use
  // to get to user space.
  
  // set S Previous Privilege mode to User.
  unsigned long x = r_sstatus();
  x &= ~SSTATUS_SPP; // clear SPP to 0 for user mode
  x |= SSTATUS_SPIE; // enable interrupts in user mode
  w_sstatus(x);

  // set S Exception Program Counter to the saved user pc.
  w_sepc(p->trapframe->epc);

  // tell trampoline.S the user page table to switch to.
  uint64 satp = MAKE_SATP(p->pagetable);

  // jump to userret in trampoline.S at the top of memory, which 
  // switches to the user page table, restores user registers,
  // and switches to user mode with sret.
  uint64 trampoline_userret = TRAMPOLINE + (userret - trampoline);
  ((void (*)(uint64))trampoline_userret)(satp);
}

// interrupts and exceptions from kernel code go here via kernelvec,
// on whatever the current kernel stack is.
void 
kerneltrap()
{
  int which_dev = 0;
  uint64 sepc = r_sepc();
  uint64 sstatus = r_sstatus();
  uint64 scause = r_scause();
  
  if((sstatus & SSTATUS_SPP) == 0)
    panic("kerneltrap: not from supervisor mode");
  if(intr_get() != 0)
    panic("kerneltrap: interrupts enabled");

  if((which_dev = devintr()) == 0){
    // interrupt or trap from an unknown source
    printf("scause=0x%lx sepc=0x%lx stval=0x%lx\n", scause, r_sepc(), r_stval());
    panic("kerneltrap");
  }

  // give up the CPU if this is a timer interrupt.
  if(which_dev == 2 && myproc() != 0)
    // printf("Im in kernel trap!\n");
  //   yield();
  // in EEVDF, yield only in user-trap
  // because switch process only in condition of process

  // the yield() may have caused some traps to occur,
  // so restore trap registers for use by kernelvec.S's sepc instruction.
  w_sepc(sepc);
  w_sstatus(sstatus);
}

void
clockintr()
{
  if(cpuid() == 0){
    acquire(&tickslock);
    ticks++;
    wakeup(&ticks);
    release(&tickslock);
  }

  // ask for the next timer interrupt. this also clears
  // the interrupt request. 1000000 is about a tenth
  // of a second.
  // for pa2, adjust time 1,000,000 to 100,000 (1/10)
  w_stimecmp(r_time() + 100000);
}

// check if it's an external interrupt or software interrupt,
// and handle it.
// returns 2 if timer interrupt,
// 1 if other device,
// 0 if not recognized.
int
devintr()
{
  uint64 scause = r_scause();

  if(scause == 0x8000000000000009L){
    // this is a supervisor external interrupt, via PLIC.

    // irq indicates which device interrupted.
    int irq = plic_claim();

    if(irq == UART0_IRQ){
      uartintr();
    } else if(irq == VIRTIO0_IRQ){
      virtio_disk_intr();
    } else if(irq){
      printf("unexpected interrupt irq=%d\n", irq);
    }

    // the PLIC allows each device to raise at most one
    // interrupt at a time; tell the PLIC the device is
    // now allowed to interrupt again.
    if(irq)
      plic_complete(irq);

    return 1;
  } else if(scause == 0x8000000000000005L){
    // timer interrupt.
    clockintr();
    return 2;
  } else {
    return 0;
  }
}
