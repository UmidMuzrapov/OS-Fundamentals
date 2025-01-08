/**
* @author Umid Muzrapov
     * Course: CS452
     * Phase 3  - User Processes and System Calls
     * Instructor: Russell Lewis
     * TA: Priya Kaushik, Junyong Zhao
     * Due Date: November 6
*
 * Operational Requirements:
     *  C99
     *  stdlib
     *  string
     *  stdio
     *  phase1.h
     *  phase2.h
     *  phase3.h
     *  usoloss
     *  usyscall.h
     *  phase3_usermode.h
*/

/****************************************
 * Macros and constants
 ***************************************/

#include <stdio.h>
#include "phase1.h"
#include "phase2.h"
#include "phase3.h"
#include <usyscall.h>
#include <usloss.h>
#include "phase3_usermode.h"
#define DEBUG 0

/****************************************
 * Structs and type definitions
 ***************************************/

typedef struct Mutex Mutex;
typedef struct Semaphore Semaphore;
typedef struct WrapperParam WrapperParam;

enum SemStatus{
    SEM_FREE,
    SEM_ALLOCATED,
};

struct Mutex{
    int mailbox_id;
};

struct Semaphore {
    int val;
    int id;
    int number_of_blocked;
    int mailbox_id;
    enum SemStatus status;
};

struct WrapperParam{
    int (*func) (void*);
    void* func_args;
};

// global variables
static Mutex global_lock;
static Semaphore semaphore_pool[MAXSEMS];
static int semaphore_id;
static WrapperParam wrapper_param_send;
static WrapperParam wrapper_param_receive;

/**
 * Prints error message and halts.
 * @param str an error message to print
 * @param code exit code
 */
void print_error(char *str, int code) {
    USLOSS_Console("%s\n", str);
    USLOSS_Halt(code);
}

/**
 * The function gains the global lock
 */
void gain_lock(){
    int result = MboxSend(global_lock.mailbox_id, NULL, 0);
    if (result!=0) print_error("Error: could not gain lock.", -1);
}

/**
 * The function releases the global lock
 */
void release_lock(){
    int result = MboxRecv(global_lock.mailbox_id, NULL, 0);
    if (result < 0) print_error("Error: could not release lock.", -1);
}

/**
 * The function returns the index of a free semaphore from the semaphore pool.
 * If none is available, return -1.
 * @return semaphore index/id. -1 if no free semaphore.
 */
static int request_semaphore_id(){
    int potential_id = semaphore_id%MAXSEMS;
    int count = 0;

    while (semaphore_pool[potential_id].status != SEM_FREE && count < MAXSEMS) {
        potential_id = (potential_id + 1) % MAXSEMS;
        count++;
    }

    return count >= MAXSEMS ? -1 : potential_id;
}

/**
 * The function grabs a free semaphore from the semaphore pool.
 * @return a pointer to semaphore
 */
Semaphore *get_free_semaphore(){
    int free_semaphore_id = request_semaphore_id();
    // ensure there is free semaphore
    if (free_semaphore_id == -1) return NULL;

    Semaphore *semaphore = &semaphore_pool[free_semaphore_id];
    semaphore->status = SEM_ALLOCATED;
    semaphore->id = free_semaphore_id;
    semaphore_id++;

    return semaphore;
}

/**
 * The function checks if a semaphore with the given id exists.
 * @param id id of the semaphore to search for
 * @return 1 if exists. 0 otherwise
 */
int semaphore_exists(int id){
    if (id < MAXSEMS && id >= 0 && semaphore_pool[id].status == SEM_ALLOCATED) {
        return 1;
    }

    return 0;
}

/**
 * Frees semaphore, resetting its status to SEM_FREE
 * @param semaphore
 */
void free_semaphore(Semaphore *semaphore){
    semaphore->status = SEM_FREE;
}

/**
 * This is a wrapper/trampoline for running the process code.
 * @param args pointer to mailbox id
 * @return
 */
static int wrapper(void *args){
    // cast args to mailbox id
    int mailbox_id = (int)(long)args;
    // receive function pointer and arguments to the function from the correct mailbox
    int result_rec = MboxRecv(mailbox_id, &wrapper_param_receive, sizeof(wrapper_param_receive));
    if (result_rec < 0) print_error("Error: could not receive.", -1);

    if (USLOSS_PsrSet(USLOSS_PSR_CURRENT_INT) != USLOSS_DEV_OK)
    {
        USLOSS_Console("ERROR: Could not disable kernel mode.\n");
        USLOSS_Halt(1);
    }

    int result = wrapper_param_receive.func(wrapper_param_receive.func_args);
    Terminate(result);
}

/**
 * This is a handler for SPAWN system call.
 * @param args
 */
void sys_spawn_handler(USLOSS_Sysargs *args){
    gain_lock();

    // prepare start function param to send
    wrapper_param_send.func_args = args->arg2;
    wrapper_param_send.func = (int (*) (void*))args->arg1;
    int mailbox_id = MboxCreate(1, MAX_MESSAGE);
    if (mailbox_id < 0) print_error("Error: could not create a mailbox.", -1);
    int result_send = MboxSend(mailbox_id, &wrapper_param_send, sizeof(wrapper_param_send));
    if (result_send!=0) print_error("Error: could send a message.", -1);

    int result = spork((char*)args->arg5, &wrapper, (void*)(long) mailbox_id, (int)(long)args->arg3, (int)(long)args->arg4);

    if (result > 0){
        args->arg1 = (void*) (long) (result);
        args->arg4 = (void*) (long) (0);
    } else {
        args->arg1 = (void*) (long) (-1);
        args->arg4 = (void*) (long) (-1);
    }

    release_lock();
}

/**
 * This is the handler for wait system call
 * @param args
 */
void sys_wait_handler(USLOSS_Sysargs* args){
    int status = 0;
    // wait until it joins one of its kids.
    int child = join(&status);

    gain_lock();

    if (child == -2){
        args->arg4 = (void*) (long) (-2);
    } else {
        args->arg1 = (void*)(long)(child);
        args->arg4 = (void*)(long )(0);
        args->arg2 = (void*)(long)(status);
    }

    release_lock();
}

/**
 * This is the handler for terminate system call
 * @param args
 */
void sys_terminate_handler(USLOSS_Sysargs* args){
    int dummy = 0;
    // continuously check until al children are joined
    while (join(&dummy)!=-2){ }
    // then quit
    quit((int)(long)args->arg1);
}

/**
 * This is the handler for the system call that creates
 * a semaphore.
 * @param args
 */
void sys_semcreate_handler(USLOSS_Sysargs* args){
    gain_lock();

    Semaphore *semaphore = get_free_semaphore();
    int value = (int) (long) args->arg1;

    // verify that there is free semaphore and value is non-negative.
    if (semaphore == NULL || value <0) {
        args->arg4 = (void*)(long )(-1);
        release_lock();
        return;
    }

    // set up semaphore and a mailbox for it
    semaphore->val = value;
    semaphore->number_of_blocked = 0;
    int mailbox_id = MboxCreate(1, 0);
    if (mailbox_id < 0) print_error("Error: could not create a mailbox.", -1);
    semaphore->mailbox_id = mailbox_id;
    args->arg1 = (void*)(long )(semaphore->id);
    args->arg4 = (void*)(long )(0);

    release_lock();
}

/**
 * This is the handler for decrementing a semaphore
 * @param args
 */
void sys_semp_handler(USLOSS_Sysargs* args){
    gain_lock();

    int semaphore_id = (int) (long) args->arg1;

    // ensure the semaphore exists
    if (semaphore_exists(semaphore_id)){
        args->arg4 = (void*)(long )(0);
        Semaphore *semaphore = &semaphore_pool[semaphore_id];
        // if the semaphore value > 0, just decrement by 1
        if (semaphore->val > 0){
            semaphore->val -= 1 ;
        } else
        {
            // increment number of blocked process by 1
            semaphore->number_of_blocked+=1;
            // release lock so that other process can gain it if needed
            release_lock();
            MboxRecv(semaphore->mailbox_id, NULL, 0);
            semaphore->val -= 1 ;
            gain_lock();
        }

    } else {
        args->arg4 = (void*)(long )(-1);
    }

    release_lock();
}

/**
 * This is the handler for incrementing a semaphore
 * @param args
 */
void sys_semv_handler(USLOSS_Sysargs* args){
    gain_lock();

    int semaphore_id = (int) (long) args->arg1;

    // ensure the semaphore exists
    if (semaphore_exists(semaphore_id)){
        args->arg4 = (void*)(long )(0);
        Semaphore *semaphore = &semaphore_pool[semaphore_id];

        // if there are processes blocked trying to P
        if (semaphore->number_of_blocked > 0){
            semaphore->number_of_blocked-=1;
            semaphore->val +=1;
            release_lock();
            // never blocks as we know there is a blocked process
            // that will get the message right away
            MboxSend(semaphore->mailbox_id, NULL, 0);
            gain_lock();

        } else {
            semaphore->val +=1;
        }

    } else {
        args->arg4 = (void*)(long )(-1);
    }

    release_lock();
}

/**
 * This is the handler for a system call that gets the time of day
 * @param args
 */
void sys_gettimeofday_handler(USLOSS_Sysargs* args){
    gain_lock();

    int current_time = currentTime();
    args->arg1 = (void*)(long )(current_time);

    release_lock();
}

/**
 * This is the handler for a system call that gets the id of the current process
 * @param args
 */
void sys_getpid_handler(USLOSS_Sysargs* args){
    gain_lock();

    int id = getpid();
    args->arg1 = (void*)(long )(id);

    release_lock();
}

/**
 * This function is called by the testcase during bootstrap,
 * before any processes are running
 */
void phase3_init(void){
    systemCallVec[SYS_SPAWN] = sys_spawn_handler;
    systemCallVec[SYS_WAIT] = sys_wait_handler;
    systemCallVec[SYS_TERMINATE] = sys_terminate_handler;
    systemCallVec[SYS_SEMCREATE] = sys_semcreate_handler;
    systemCallVec[SYS_SEMP] = sys_semp_handler;
    systemCallVec[SYS_SEMV] = sys_semv_handler;
    systemCallVec[SYS_GETTIMEOFDAY] = sys_gettimeofday_handler;
    systemCallVec[SYS_GETPID] = sys_getpid_handler;

    // set up a global mailbox
    int id = MboxCreate(1, 0);
    if (id < 0) print_error("Error: could not create a mailbox.", -1);
    global_lock.mailbox_id = id;
}

void phase3_start_service_processes(void) { }
