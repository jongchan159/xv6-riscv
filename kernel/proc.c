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

struct cpu cpus[NCPU];

struct proc proc[NPROC];

struct proc *initproc;

int nextpid = 1;
struct spinlock pid_lock;

extern void forkret(void);
static void freeproc(struct proc *p);

extern char trampoline[]; // trampoline.S

// helps ensure that wakeups of wait()ing
// parents are not lost. helps obey the
// memory model when using p->parent.
// must be acquired before any p->lock.
struct spinlock wait_lock;

/* pa1 global variable */
struct run {
  struct run *next;
};

extern struct {
  struct spinlock lock;
  struct run *freelist;
} kmem;

/* pa2 global variable */ 
// Time to be the standard for the whole system
// The unit is "tick"
uint64 global_vruntime;

// updatd global vruntime when return to loop in scheduler()
static void update_gvt(void){
  struct proc *p;
  uint64 min_gvt = -1;           // min vruntime
  uint64 weighted_diff = 0;
  uint64 total_weight = 0;

  // 1. min_gvt calculation
  for(p = proc; p < &proc[NPROC]; p++) {
    if(p->state == RUNNABLE || p->state == RUNNING) {
      if(p->vruntime < min_gvt)
        min_gvt = p->vruntime;
    }
  }
  // if there is not runnable process is queue
  if(min_gvt == -1)
    return;

  // 2. weighted sum calculation
  for(p = proc; p < &proc[NPROC]; p++) {
    if(p->state == RUNNABLE || p->state == RUNNING) {
      uint64 diff = p->vruntime - min_gvt;
      weighted_diff += diff * p->weight;
      total_weight += p->weight;
    }
  }

  // 3. global_vruntime
  // printf("DEBUG: update global_vruntime\n");
  if(total_weight > 0)
   global_vruntime = min_gvt + (weighted_diff / total_weight);
  else
    global_vruntime = min_gvt;
}


// Allocate a page for each process's kernel stack.
// Map it high in memory, followed by an invalid
// guard page.
void
proc_mapstacks(pagetable_t kpgtbl)
{
  struct proc *p;
  
  for(p = proc; p < &proc[NPROC]; p++) {
    char *pa = kalloc();
    if(pa == 0)
      panic("kalloc");
    uint64 va = KSTACK((int) (p - proc));
    kvmmap(kpgtbl, va, (uint64)pa, PGSIZE, PTE_R | PTE_W);
  }
}

// initialize the proc table.
// Runs only at the initial kernel booting.
void
procinit(void)
{
  struct proc *p;
  
  initlock(&pid_lock, "nextpid");
  initlock(&wait_lock, "wait_lock");
  for(p = proc; p < &proc[NPROC]; p++) {
      initlock(&p->lock, "proc");
      p->state = UNUSED;
      p->kstack = KSTACK((int) (p - proc));
  }
}

// Must be called with interrupts disabled,
// to prevent race with process being moved
// to a different CPU.
int
cpuid()
{
  int id = r_tp();
  return id;
}

// Return this CPU's cpu struct.
// Interrupts must be disabled.
struct cpu*
mycpu(void)
{
  int id = cpuid();
  struct cpu *c = &cpus[id];
  return c;
}

// Return the current struct proc *, or zero if none.
struct proc*
myproc(void)
{
  push_off();
  struct cpu *c = mycpu();
  struct proc *p = c->proc;
  pop_off();
  return p;
}

int
allocpid()
{
  int pid;
  
  acquire(&pid_lock);
  pid = nextpid;
  nextpid = nextpid + 1;
  release(&pid_lock);

  return pid;
}

// Look in the process table for an UNUSED proc.
// If found, initialize state required to run in the kernel,
// and return with p->lock held.
// If there are no free procs, or a memory allocation fails, return 0.
static struct proc*
allocproc(void)
{
  struct proc *p;

  for(p = proc; p < &proc[NPROC]; p++) {
    acquire(&p->lock);
    if(p->state == UNUSED) {
      goto found;
    } else {
      release(&p->lock);
    }
  }
  return 0;

found:
  p->pid = allocpid();
  p->state = USED;
  // pa1 - default nice initialization
  p->nice = 20;
  // pa2 - scheduler variable initialization
  p->weight = nice_to_weight[p->nice];
  p->time_slice = BASE_SLICE * 1000;
  p->runtime = 0;
  p->vruntime = 0; // gvt or 0?
  p->lag = 0;
  p->vdeadline = p->vruntime + p->time_slice; // 1024/weight == 1

  // Allocate a trapframe page.
  if((p->trapframe = (struct trapframe *)kalloc()) == 0){
    freeproc(p);
    release(&p->lock);
    return 0;
  }

  // An empty user page table.
  p->pagetable = proc_pagetable(p);
  if(p->pagetable == 0){
    freeproc(p);
    release(&p->lock);
    return 0;
  }

  // Set up new context to start executing at forkret,
  // which returns to user space.
  memset(&p->context, 0, sizeof(p->context));
  p->context.ra = (uint64)forkret;
  p->context.sp = p->kstack + PGSIZE;

  return p;
}

// free a proc structure and the data hanging from it,
// including user pages.
// p->lock must be held.
static void
freeproc(struct proc *p)
{
  if(p->trapframe)
    kfree((void*)p->trapframe);
  p->trapframe = 0;
  if(p->pagetable)
    proc_freepagetable(p->pagetable, p->sz);
  p->pagetable = 0;
  p->sz = 0;
  p->pid = 0;
  p->parent = 0;
  p->name[0] = 0;
  p->chan = 0;
  p->killed = 0;
  p->xstate = 0;
  p->state = UNUSED;
  // pa1 & pa2 variable free
  p->nice = 0;
  p->weight = 0;
  p->time_slice = 0;
  p->runtime = 0;
  p->vdeadline = 0;
  p->vruntime = 0;
  p->lag = 0;
}

// Create a user page table for a given process, with no user memory,
// but with trampoline and trapframe pages.
pagetable_t
proc_pagetable(struct proc *p)
{
  pagetable_t pagetable;

  // An empty page table.
  pagetable = uvmcreate();
  if(pagetable == 0)
    return 0;

  // map the trampoline code (for system call return)
  // at the highest user virtual address.
  // only the supervisor uses it, on the way
  // to/from user space, so not PTE_U.
  if(mappages(pagetable, TRAMPOLINE, PGSIZE,
              (uint64)trampoline, PTE_R | PTE_X) < 0){
    uvmfree(pagetable, 0);
    return 0;
  }

  // map the trapframe page just below the trampoline page, for
  // trampoline.S.
  if(mappages(pagetable, TRAPFRAME, PGSIZE,
              (uint64)(p->trapframe), PTE_R | PTE_W) < 0){
    uvmunmap(pagetable, TRAMPOLINE, 1, 0);
    uvmfree(pagetable, 0);
    return 0;
  }

  return pagetable;
}

// Free a process's page table, and free the
// physical memory it refers to.
void
proc_freepagetable(pagetable_t pagetable, uint64 sz)
{
  uvmunmap(pagetable, TRAMPOLINE, 1, 0);
  uvmunmap(pagetable, TRAPFRAME, 1, 0);
  uvmfree(pagetable, sz);
}

// a user program that calls exec("/init")
// assembled from ../user/initcode.S
// od -t xC ../user/initcode
uchar initcode[] = {
  0x17, 0x05, 0x00, 0x00, 0x13, 0x05, 0x45, 0x02,
  0x97, 0x05, 0x00, 0x00, 0x93, 0x85, 0x35, 0x02,
  0x93, 0x08, 0x70, 0x00, 0x73, 0x00, 0x00, 0x00,
  0x93, 0x08, 0x20, 0x00, 0x73, 0x00, 0x00, 0x00,
  0xef, 0xf0, 0x9f, 0xff, 0x2f, 0x69, 0x6e, 0x69,
  0x74, 0x00, 0x00, 0x24, 0x00, 0x00, 0x00, 0x00,
  0x00, 0x00, 0x00, 0x00
};

// Set up first user process.
void
userinit(void)
{
  struct proc *p;

  p = allocproc();
  initproc = p;
  
  // allocate one user page and copy initcode's instructions
  // and data into it.
  uvmfirst(p->pagetable, initcode, sizeof(initcode));
  p->sz = PGSIZE;

  // prepare for the very first "return" from kernel to user.
  p->trapframe->epc = 0;      // user program counter
  p->trapframe->sp = PGSIZE;  // user stack pointer

  safestrcpy(p->name, "initcode", sizeof(p->name));
  p->cwd = namei("/");

  p->state = RUNNABLE;

  release(&p->lock);
}

// Grow or shrink user memory by n bytes.
// Return 0 on success, -1 on failure.
int
growproc(int n)
{
  uint64 sz;
  struct proc *p = myproc();

  sz = p->sz;
  if(n > 0){
    if((sz = uvmalloc(p->pagetable, sz, sz + n, PTE_W)) == 0) {
      return -1;
    }
  } else if(n < 0){
    sz = uvmdealloc(p->pagetable, sz, sz + n);
  }
  p->sz = sz;
  return 0;
}

// Create a new process, copying the parent.
// Sets up child kernel stack to return as if from fork() system call.
int
fork(void)
{
  //printf("DEBUG: start in fork()\n");
  int i, pid;
  struct proc *np; // child(new) process
  struct proc *p = myproc(); // parent process

  // Allocate process.
  if((np = allocproc()) == 0){
    return -1;
  }

  // Copy user memory from parent to child.
  if(uvmcopy(p->pagetable, np->pagetable, p->sz) < 0){
    freeproc(np);
    release(&np->lock);
    return -1;
  }
  np->sz = p->sz;

  // copy saved user registers.
  *(np->trapframe) = *(p->trapframe);

  // Cause fork to return 0 in the child.
  np->trapframe->a0 = 0;

  // increment reference counts on open file descriptors.
  for(i = 0; i < NOFILE; i++)
    if(p->ofile[i])
      np->ofile[i] = filedup(p->ofile[i]);
  np->cwd = idup(p->cwd);

  // copy nice value
  np->nice = p->nice;
  // copy scheduler value
  np->weight = nice_to_weight[np->nice];
  np->runtime = 0;
  np->vruntime = p->vruntime;
  np->time_slice = BASE_SLICE * 1000;
  np->lag = global_vruntime - np->vruntime;
  np->vdeadline = np->vruntime + (np->time_slice * 1024) / np->weight;

  safestrcpy(np->name, p->name, sizeof(p->name));

  pid = np->pid;

  release(&np->lock);

  acquire(&wait_lock);
  np->parent = p;
  release(&wait_lock);

  acquire(&np->lock);
  np->state = RUNNABLE;
  release(&np->lock);

  /* pa3 - copy mmap area
  1. 부모 프로세스의 페이지 테이블을 복제 -> uvmcopy
  2. 부모와 같은 물리 페이지를 매핑 -> uvmcopy
  3. 자식 프로세스의 메모리 공간 할당 -> mmap_area[i]
  */
  np->pagetable = proc_pagetable(np);            // create new page table
  uvmcopy(p->pagetable, np->pagetable, p->sz);   // copy parent's page table & frames
  np->sz = p->sz;                                // copy parent's PT size
  for (int i = 0; i < MMAP_AREA_MAX; i++) {
    np->mmap_area[i] = p->mmap_area[i];  // mmap 영역 복사
  } 
  return pid;
}

// Pass p's abandoned children to init.
// Caller must hold wait_lock.
void
reparent(struct proc *p)
{
  struct proc *pp;

  for(pp = proc; pp < &proc[NPROC]; pp++){
    if(pp->parent == p){
      pp->parent = initproc;
      wakeup(initproc);
    }
  }
}

// Exit the current process.  Does not return.
// An exited process remains in the zombie state
// until its parent calls wait().
void
exit(int status)
{
  struct proc *p = myproc();

  if(p == initproc)
    panic("init exiting");

  // Close all open files.
  for(int fd = 0; fd < NOFILE; fd++){
    if(p->ofile[fd]){
      struct file *f = p->ofile[fd];
      fileclose(f);
      p->ofile[fd] = 0;
    }
  }

  begin_op();
  iput(p->cwd);
  end_op();
  p->cwd = 0;

  acquire(&wait_lock);

  // Give any children to init.
  reparent(p);

  // Parent might be sleeping in wait().
  wakeup(p->parent);
  
  acquire(&p->lock);

  p->xstate = status;
  p->state = ZOMBIE;

  release(&wait_lock);

  // Jump into the scheduler, never to return.

  //printf("DEBUG: shced in exit\n");
  sched();
  panic("zombie exit");
}

// Wait for a child process to exit and return its pid.
// Return -1 if this process has no children.
int
wait(uint64 addr)
{
  struct proc *pp;
  int havekids, pid;
  struct proc *p = myproc();

  acquire(&wait_lock);

  for(;;){
    // Scan through table looking for exited children.
    havekids = 0;
    for(pp = proc; pp < &proc[NPROC]; pp++){
      if(pp->parent == p){
        // make sure the child isn't still in exit() or swtch().
        acquire(&pp->lock);

        havekids = 1;
        if(pp->state == ZOMBIE){
          // Found one.
          pid = pp->pid;
          if(addr != 0 && copyout(p->pagetable, addr, (char *)&pp->xstate,
                                  sizeof(pp->xstate)) < 0) {
            release(&pp->lock);
            release(&wait_lock);
            return -1;
          }
          freeproc(pp);
          release(&pp->lock);
          release(&wait_lock);
          return pid;
        }
        release(&pp->lock);
      }
    }

    // No point waiting if we don't have any children.
    if(!havekids || killed(p)){
      release(&wait_lock);
      return -1;
    }
    
    // Wait for a child to exit.
    sleep(p, &wait_lock);  //DOC: wait-sleep
  }
}

// Per-CPU process scheduler.
// Each CPU calls scheduler() after setting itself up.
// Scheduler never returns.  It loops, doing:
//  - choose a process to run.
//  - swtch to start running that process.
//  - eventually that process transfers control
//    via swtch back to the scheduler.
void
scheduler(void)
{
  struct proc *p;
  struct cpu *c = mycpu();

  c->proc = 0;

  while(mycpu()->noff > 0){
    pop_off();
  }

  for(;;){
    // The most recent process to run may have had interrupts
    // turned off; enable them to avoid a deadlock if all
    // processes are waiting.
    intr_on();

    // 0. update global_vruntime
    update_gvt();

    // 1. all process's lag update
    for(p = proc; p < &proc[NPROC]; p++) {
      if(p->state == RUNNABLE || p->state == RUNNING){
        acquire(&p->lock);
        p->lag = global_vruntime - p->vruntime;
        release(&p->lock); 
      }
    }

    struct proc *best = 0;
    int found = 0;
    for(p = proc; p < &proc[NPROC]; p++) {
      acquire(&p->lock);
      // 2. add condition to check eligiblity
      uint16 is_eligible = ((p->state == RUNNABLE || p->state == RUNNING) && p->lag >= 0);

      // 3. if eligible then find shortest vdeadline
      if(is_eligible && (best == 0 || p->vdeadline < best->vdeadline)) {
        best = p;
        // if same vdeadline, the process preceding the runnable queue is executed.
      }
      release(&p->lock); 
    }
    
    if(best != 0){
      // Switch to chosen process.  It is the process's job
      // to release its lock and then reacquire it
      // before jumping back to us.
      /*if(schedbit){
      	printf("\nDEBUG: best process is %s %d\n=================\n", best->name, best->pid);
	schedbit = 0;
      }*/

      acquire(&best->lock);
      c->proc = best;
      best->state = RUNNING;
      best->vdeadline = best->vruntime + ((best->time_slice * 1024) / best->weight);
      // printf("DEBUG: now best swtch in scheduler()\n");
      swtch(&c->context, &best->context);

      // Process is done running for now.
      // It should have changed its p->state before coming back.
      c->proc = 0;
      found = 1;
      //printf("DEBUG: release best lock in scheduler()\n");
      release(&best->lock);
      //printf("DEBUG: successfully release best lock in scheduler()\n");
    }
  
    if(found == 0) {
      // nothing to run; stop running on this core until an interrupt.
      intr_on();
      asm volatile("wfi");
    }
  }
}

// Switch to scheduler.  Must hold only p->lock
// and have changed proc->state. Saves and restores
// intena because intena is a property of this
// kernel thread, not this CPU. It should
// be proc->intena and proc->noff, but that would
// break in the few places where a lock is held but
// there's no process.
void
sched(void)
{
  int intena;
  //printf("DEBUG: myproc() in sched, mycpu()->noff: %d\n", mycpu()->noff);
  struct proc *p = myproc();

  /*
  if(mycpu()->noff > 1){
    //printf("DEBUG: over noff() in sched(), mycpu()->noff: %d\n", mycpu()->noff);
    pop_off();
  }*/

  //printf("DEBUG: process %s %d problem in sched()\n", p->name, p->pid);
  if(!holding(&p->lock))
    panic("sched p->lock");
  if(mycpu()->noff != 1){
    //printf("DEBUG: sched locks in %s %d\n", p->name, p->pid);
    panic("sched locks");
  }
  if(p->state == RUNNING)
    panic("sched running");
  if(intr_get())
    panic("sched interruptible");

  intena = mycpu()->intena; 
  //printf("DEBUG: problem in sched() at swtch, mycpu()->noff: %d\n", mycpu()->noff);
  swtch(&p->context, &mycpu()->context); // define as assembly
  //printf("DEBUG: success in sched() at swtch, mycpu()->noff: %d\n", mycpu()->noff);
  mycpu()->intena = intena;
}

// Give up the CPU for one scheduling round.
void
yield(void)
{
  // printf("DEBUG: in yield\n");
  //printf("DEBUG: myproc() in yield, mycpu()->noff: %d\n", mycpu()->noff);
  struct proc *p = myproc();
  // double acquire or sched prevention
  if (mycpu()->noff > 1){
    printf("DEBUG: Wrong Yield - noff: %d\n",mycpu()->noff);
    return;
  }

  acquire(&p->lock);
  p->state = RUNNABLE;
  //printf("DEBUG: in yield, sched() before check, noff: %d\n", mycpu()->noff);
  sched();
  release(&p->lock);
}

// A fork child's very first scheduling by scheduler()
// will swtch to forkret.
void
forkret(void)
{
  static int first = 1;

  // Still holding p->lock from scheduler.
  release(&myproc()->lock);

  if (first) {
    // File system initialization must be run in the context of a
    // regular process (e.g., because it calls sleep), and thus cannot
    // be run from main().
    fsinit(ROOTDEV);

    first = 0;
    // ensure other cores see first=0.
    __sync_synchronize();
  }

  usertrapret();
}

// Atomically release lock and sleep on chan.
// Reacquires lock when awakened.
void
sleep(void *chan, struct spinlock *lk)
{
//	schedbit = 1;
//	printf("\n sleep and go scheduler() \n");
  //printf("DEBUG: myproc() in sleep, mycpu()->noff: %d\n", mycpu()->noff);
  struct proc *p = myproc();
  
  // Must acquire p->lock in order to
  // change p->state and then call sched.
  // Once we hold p->lock, we can be
  // guaranteed that we won't miss any wakeup
  // (wakeup locks p->lock),
  // so it's okay to release lk.
  //printf("DEBUG: process %s %d is acquire in sleep\n", p->name, p->pid);
  acquire(&p->lock);  //DOC: sleeplock1
  release(lk);

  // Go to sleep.
  p->chan = chan;
  p->state = SLEEPING;

  // very parameters will remain saved, even if is a non-eiligible process
  // that means not have to do handling separately.
  //printf("DEBUG: process %s %d is shced in sleep\n", p->name, p->pid);
  //printf("DEBUG: process %s %d is before sched() in sleep\n", p->name, p->pid);
  sched();

  // Tidy up.
  p->chan = 0;

  // Reacquire original lock.f
  release(&p->lock);
  acquire(lk);

  // printf("in sleep() after push_off, mycpu()->noff: %d \n", mycpu()->noff);
}

// Wake up all processes sleeping on chan.
// Must be called without any p->lock.
void
wakeup(void *chan)
{
  struct proc *p;

  for(p = proc; p < &proc[NPROC]; p++) {
    if(p != myproc()){
      if(mycpu()->noff!=1){
        //printf("DEBUG: myproc() issue in wakeup\n");
      }
      acquire(&p->lock);
      if(p->state == SLEEPING && p->chan == chan) {
        //printf("DEBUG: in wakeup()\n");
        p->state = RUNNABLE;
        // pa2-cond2 : Handling about woken process
        // its virtual runtime and nice value remain the same before sleeping
        // get default time slice
        // vdeadline and eligibility(lag) should be recalculated
        p->time_slice = BASE_SLICE * 1000;
        p->vdeadline = p->vruntime + (p->time_slice * 1024 / p->weight);
        p->lag = global_vruntime - p->vruntime;
        /*
        why update vdeadline?
        -> if process went to sleep before using up time slice
        vdeadline may not have been updated.
        */
      }
      release(&p->lock);
    }
  }
}

// Kill the process with the given pid.
// The victim won't exit until it tries to return
// to user space (see usertrap() in trap.c).
int
kill(int pid)
{
  struct proc *p;

  for(p = proc; p < &proc[NPROC]; p++){
    acquire(&p->lock);
    if(p->pid == pid){
      p->killed = 1;
      if(p->state == SLEEPING){
        // Wake process from sleep().
        p->state = RUNNABLE;
      }
      release(&p->lock);
      return 0;
    }
    release(&p->lock);
  }
  return -1;
}

void
setkilled(struct proc *p)
{
  acquire(&p->lock);
  p->killed = 1;
  release(&p->lock);
}

int
killed(struct proc *p)
{
  int k;
  
  acquire(&p->lock);
  k = p->killed;
  release(&p->lock);
  return k;
}

// Copy to either a user address, or kernel address,
// depending on usr_dst.
// Returns 0 on success, -1 on error.
int
either_copyout(int user_dst, uint64 dst, void *src, uint64 len)
{
  struct proc *p = myproc();
  if(user_dst){
    return copyout(p->pagetable, dst, src, len);
  } else {
    memmove((char *)dst, src, len);
    return 0;
  }
}

// Copy from either a user address, or kernel address,
// depending on usr_src.
// Returns 0 on success, -1 on error.
int
either_copyin(void *dst, int user_src, uint64 src, uint64 len)
{
  struct proc *p = myproc();
  if(user_src){
    return copyin(p->pagetable, dst, src, len);
  } else {
    memmove(dst, (char*)src, len);
    return 0;
  }
}

// Print a process listing to console.  For debugging.
// Runs when user types ^P on console.
// No lock to avoid wedging a stuck machine further.
void
procdump(void)
{
  static char *states[] = {
  [UNUSED]    "unused",
  [USED]      "used",
  [SLEEPING]  "sleep ",
  [RUNNABLE]  "runble",
  [RUNNING]   "run   ",
  [ZOMBIE]    "zombie"
  };
  struct proc *p;
  char *state;

  printf("\n");
  for(p = proc; p < &proc[NPROC]; p++){
    if(p->state == UNUSED)
      continue;
    if(p->state >= 0 && p->state < NELEM(states) && states[p->state])
      state = states[p->state];
    else
      state = "???";
    printf("%d %s %s", p->pid, state, p->name);
    printf("\n");
  }
}

// PA1-1 : getnice
// get process's nice value
// nice is priority of scheduling
// lower nice has higher priority
int
getnice(int pid)
{
	struct proc *p;
  
  // loop when p has a "pid"
  for(p = proc; p < &proc[NPROC]; p++){
    acquire(&p->lock);
    if(p->state != UNUSED && p->pid == pid){ // success
      release(&p->lock);
      return p->nice; 
    }
    release(&p->lock);
  } 
  // fail case
  return -1;
}

// PA1-2 : setnice
// set process's nice value
int 
setnice(int pid, int value)
{
	struct proc *p;
  
  if(value < 0 || value > 39) {
    // fail case - over or under value
    return -1;
  }
  else {
    // loop when p has a "pid"
    for(p = proc; p < &proc[NPROC]; p++){
      acquire(&p->lock);
      if(p->state != UNUSED && p->pid == pid){ // success
        release(&p->lock);
        p->nice = value;
        // set weight for pa2
        p->weight = nice_to_weight[p->nice];
        p->vdeadline = p->vruntime + (p->time_slice * 1024) / p->weight;
        return 0;
      }
      release(&p->lock);
    }
    // fail case - no proc
    return -1;
  }
}

// PA1-3 : ps
// print(name, pid, state, priority(nice value))
// no pid -> no print
// pid == 0 -> print out all process
void ps(int pid)
{
  //printf("DEBUG: shced in ps\n");
  static char *states[] = {
    [UNUSED]    "unused",
    [USED]      "used",
    [SLEEPING]  "sleep ",
    [RUNNABLE]  "runble",
    [RUNNING]   "run   ",
    [ZOMBIE]    "zombie"
    };

	struct proc *p;

  if(!mycpu()->noff){
    push_off();
    //printf("DEBUG: push_off in ps\n");
  }
  if(pid != 0) // print out one process
  {
    printf("name     pid    state    priority runtime/weight runtime    vruntime   vdeadline  is_eligible   tick %d\n", ticks * 1000);
    for(p = proc; p < &proc[NPROC]; p++){
      acquire(&p->lock);
      if(p->state != UNUSED && p->pid == pid){ // success    
        // name
        printf("%s", p->name);
        for(int i = strlen(p->name); i < 9; i++) printf(" ");

        // pid
        printf("%d", p->pid);
        if(p->pid < 10) printf("      ");
        else if(p->pid < 100) printf("     ");
        else printf("    ");

        // state
        char *st = states[p->state];
        printf("%s", st);
        for(int i = strlen(st); i < 9; i++) printf(" ");

        // priority (nice)
        printf("%d", p->nice);
        if(p->nice < 10) printf("        ");
        else printf("       ");

        // runtime/weight
        int rtw = (int)(p->vruntime / (p->weight ? p->weight : 1));
        printf("%d", rtw);
        if(rtw < 10) printf("              ");
        else if(rtw < 100) printf("             ");
        else if(rtw < 1000) printf("            ");
        else printf("           ");

        // runtime
        printf("%d", p->runtime);
        if(p->runtime < 10) printf("          ");
        else if(p->runtime < 100) printf("         ");
        else if(p->runtime < 1000) printf("        ");
        else printf("       ");

        // vruntime
        printf("%d", p->vruntime);
        if(p->vruntime < 10) printf("          ");
        else if(p->vruntime < 100) printf("         ");
        else if(p->vruntime < 1000) printf("        ");
        else printf("       ");

        // vdeadline
        printf("%d", p->vdeadline);
        if(p->vdeadline < 10) printf("          ");
        else if(p->vdeadline < 100) printf("         ");
        else if(p->vdeadline < 1000) printf("        ");
        else printf("       ");

        // eligibility
        printf("%s\n", p->lag >= 0 ? "true" : "false");
      } 
      release(&p->lock);
    }
  }
  else // pid == 0 -> print out all process
  {
    printf("name     pid    state    priority runtime/weight runtime    vruntime   vdeadline  is_eligible   tick %d\n", ticks * 1000);

    for(p = proc; p < &proc[NPROC]; p++){
      acquire(&p->lock);
      if(p->state != UNUSED){ // success
        // name
        printf("%s", p->name);
        for(int i = strlen(p->name); i < 9; i++) printf(" ");

        // pid
        printf("%d", p->pid);
        if(p->pid < 10) printf("      ");
        else if(p->pid < 100) printf("     ");
        else printf("    ");

        // state
        char *st = states[p->state];
        printf("%s", st);
        for(int i = strlen(st); i < 9; i++) printf(" ");

        // priority (nice)
        printf("%d", p->nice);
        if(p->nice < 10) printf("        ");
        else printf("       ");

        // runtime/weight
        int rtw = (int)(p->vruntime / (p->weight ? p->weight : 1));
        printf("%d", rtw);
        if(rtw < 10) printf("              ");
        else if(rtw < 100) printf("             ");
        else if(rtw < 1000) printf("            ");
        else printf("           ");

        // runtime
        printf("%d", p->runtime);
        if(p->runtime < 10) printf("          ");
        else if(p->runtime < 100) printf("         ");
        else if(p->runtime < 1000) printf("        ");
        else printf("       ");

        // vruntime
        printf("%d", p->vruntime);
        if(p->vruntime < 10) printf("          ");
        else if(p->vruntime < 100) printf("         ");
        else if(p->vruntime < 1000) printf("        ");
        else printf("       ");

        // vdeadline
        printf("%d", p->vdeadline);
        if(p->vdeadline < 10) printf("          ");
        else if(p->vdeadline < 100) printf("         ");
        else if(p->vdeadline < 1000) printf("        ");
        else printf("       ");

        // eligibility
        printf("%s\n", p->lag >= 0 ? "true" : "false");
      }
      release(&p->lock);
    }
  }
  pop_off();
}

// PA1-4 : meminfo
// print available memory
// return memory in byte
// memory is allocated when process arrived
// go round run and meet freelist then += PGSIZE
uint64 
meminfo(void)
{
  uint64 freemem = 0;
  struct run *r;

  acquire(&kmem.lock);
  r = kmem.freelist;
  while(r) {
    freemem += PGSIZE; // #define PGSIZE 4096
    r = r->next;
  }
  release(&kmem.lock);

  // printf("available memory : %lu bytes \n", freemem);
  return freemem;
}

// PA1-5 : waitpid
// wait process(pid) if that is child process then return 0
// no pid and have no permission then return -1
// similar to wait() but method about pp not about p
int 
waitpid(int pid)
{
  struct proc *p; // child (maybe)
  struct proc *pp = myproc(); // parent process

  acquire(&wait_lock);

  for(p = proc; p < &proc[NPROC]; p++){
    if(p->state != UNUSED && p->pid == pid){
      if(p->parent != pp){ // no permission
        release(&wait_lock);
        return -1;
      }
      // loop when p become zombie (wait())
      for(;;){
        acquire(&p->lock);
        if(p->state == ZOMBIE){
          freeproc(p);
          release(&p->lock);
          release(&wait_lock);
          return 0;
        }
        release(&p->lock);
        sleep(pp, &wait_lock);
      }
    }
  }
  // no process
  release(&wait_lock);
  return -1;
}

/**
 * PA3 - Virtual Memory
 * mmap()
 * munmap()
 * freemem()
 */

/*
mmap() - map a file into memory
*/
uint64 mmap(uint64 addr, int length, int prot, int flags, int fd, int offset){
	struct proc *p = myproc();
  	struct file *f = 0;
	
	// 1&2. addr & length validity check
	if(addr % PGSIZE != 0 || length % PGSIZE != 0)
		return -1;
	
	if(addr < 0 || length <= 0)
		return -1;
		
	if(addr > MAXVA - length)
		return -1;
	
	// 4&5. flags 체크
	// anonymous
  	if (flags & MAP_ANONYMOUS) {
    		if (fd != -1 || offset != 0) // fd 값 유효하지 않음
      			return -1;
    		f = 0;
  	} 
  	// file mapping (!anonymous)
  	else {
    		if (fd < 0 || fd >= NOFILE) // fd 값 유효하지 않음
      			return -1;
    		f = p->ofile[fd];
    		if ((prot & PROT_READ) && !f->readable) // 읽기 권한 불일치
	    		return -1;
    		if ((prot & PROT_WRITE) && !f->writable) // 읽기 권한 불일치
	    		return -1;
  	}
  
  	struct mmap_area *ma = 0; // 탐색 실패 시 반환을 위한 초기화
  	for(int i = 0; i < MMAP_AREA_MAX; i++){
	  if (p->mmap_area[i].length == 0) {
     	  	ma = &p->mmap_area[i];
      	  	break;
    	  }
  	}
  	if (!ma)
    		return -1; // no available mmap_area
  
        // printf("DBG: MMAPBASE = 0x%x, convert to address = %p\n", MMAPBASE, (void *)MMAPBASE);	
  	uint64 va_start = MMAPBASE + addr;  
  	ma->addr = va_start;
  	ma->length = length;
  	ma->offset = offset;
 	ma->prot = prot;
  	ma->flags = flags;
  	ma->f = f;
  	ma->p = p;
  
  	if (f)
    		filedup(f);
  
	if (flags & MAP_POPULATE) {
	  // populate
		for (int i = 0; i < length / PGSIZE; i++) {
			// 물리 메모리에 할당
			uint64 va = va_start + i*PGSIZE;
			
			/*
			// OOM check
			int pages_num = length / PGSIZE;
			if(pages_num > freemem()){
				return -1;
			}*/
		  	char *mem = kalloc();
		  	if(!mem) {
			  printf("kalloc failed in mmap()\n");
			  return -1;
	  	 	}

		  	int perm = PTE_U;
      		  	if(prot & PROT_READ) perm |= PTE_R;
      		  	if(prot & PROT_WRITE) perm |= PTE_W;
      
			memset(mem, 0, PGSIZE);
			
			/*
			// double-mapping 방지
			pte_t *pte = walk(p->pagetable, va, 1);
			if (pte && (*pte & PTE_V)) {
  			// 이미 매핑된 페이지
				printf("double mapping");
  				kfree(mem);
  				return -1;
			}*/

			if(mappages(p->pagetable, va, PGSIZE, (uint64)mem, perm) < 0){
				printf("mappages failed in mmap()\n");
				kfree(mem);
				return -1;
			}
			// file mapping
			if(f) {
				ilock(f->ip);
				readi(f->ip, 0, (uint64)mem, offset + i*PGSIZE, PGSIZE);
				iunlock(f->ip);
			}
	  } // for
	}
	else {
		// lazily allocation(!populate)
		return va_start;
	}
	
	return va_start;
}	

/*
munmap() - unmap a file from memory
*/
int munmap(uint64 addr){
	struct proc *p = myproc();
	
	// 1. addr 유효성 검사
	if(addr % PGSIZE != 0 || addr < 0 || addr >= MAXVA)
		return -1;
		
	// 2. mapping area 탐색
	struct mmap_area *ma = 0; // 탐색 실패 시 반환을 위해 0 초기화
	uint64 va_start = addr;
	
  	for(int i = 0; i < MMAP_AREA_MAX; i++){
	  if (p->mmap_area[i].addr == va_start) {
      		ma = &p->mmap_area[i];
      		break;
    	  }
  	}
  	if (!ma)
    		return -1; // no available mmap_area
	
	// uvmunmap(p->pagetable, addr, ma->length / PGSIZE, 0);
  
  	// 3. 매핑 영역 안에서 물리 프레임 loop 검사
  	for (uint64 va = va_start; va < va_start + ma->length; va += PGSIZE) {
    		pte_t *pte = walk(p->pagetable, va, 0);
		if (pte == 0) continue;

    		if ((*pte & PTE_V) && (*pte & PTE_U)) { // PTE_V -> VALID, PTE_U -> 유저만 접근 가능
        		// 3-1. PTE 존재 && 물리 프레임 존재 -> 해제
        		uvmunmap(p->pagetable, va, 1, 1); // PTE + 프레임 모두 해제 (1page 단위)
        		// kfree는 uvmunmap() 안에서 실행
			// char *pa = (char *)PTE2PA(*pte);
			// kfree(pa);
    		}
  	}
  	// 4. mmap_area() 해제
  	memset(ma, 0, sizeof(*ma));
  
  	// 5. return
	return 1;
}

/*
freemem() - free page counting
*/
int freemem(void){
	struct run *r;
	int cnt = 0;
	
	acquire(&kmem.lock);
	for(r = kmem.freelist; r; r = r->next){
		cnt++;
	}
	release(&kmem.lock);
	
	return cnt;
}
