/**
* @author Umid Muzrapov
     * Course: CS452
     * Phase 1 b
     * Instructor: Russell Lewis
     * TA: Priya Kaushik, Junyong Zhao
     * Due Date: Oct 4
 *
* Description: The program implements a number of functions for the first phase of the project.:
     * phase1_init
     * dispatcher
     * spork
     * join
     * zap
     * quit
     * getpid
     * dumpProcess
     * blockMe
     * unblockProc
     *
*
 * Operational Requirements:
     *  C99
     *  stdlib
     *  string
     *  stdio
     *  phase1.h
     *  usoloss
*/

#include "phase1.h"
#include <stdlib.h>
#include <string.h>
#include <stdio.h>

/*******************************
 * This section defines data structures and macros necessary for phase 1 of the project
 *
 ********************************/
enum ProcessState {
    FREE = 0,
    READY = 1,
    RUNNING = 2,
    BLOCKED = 3,
    TERM = 4,
};

enum ProcessPriority {
    ONE = 1,
    TWO = 2,
    THREE = 3,
    FOUR = 4,
    FIVE = 5,
    SIX = 6,
};

enum BlockReason {
    NONE = 0,
    NO_DEAD_CHILD = 1,
    ZAP_INCOMPLETE_PROCESS = 2,
    SELF_BLOCKED = 3,
};

typedef struct MyPCB MyPCB;

struct MyPCB {
    int process_id;
    int exit_status;
    char name[MAXNAME];
    MyPCB *first_child;
    MyPCB *parent;
    MyPCB *next_sibling;
    MyPCB *prev_sibling;
    MyPCB *next_in_queue;
    MyPCB *next_in_block;
    enum BlockReason block_reason;
    enum ProcessState process_state;
    enum ProcessPriority process_priority;
    void *stack;
    int run_start_time;
    int who_blocked;

    int (*start_func)(void *);

    void *args;
    USLOSS_Context context;
};

#define INIT_PRIORITY 6
#define INIT_PROCESS_ID 1
#define USER_MODE_ERROR 1
#define ERROR_STATE 1
#define MAX_STATUS_LENGTH 300
#define DEBUG 0

int next_id = 2;
MyPCB *current_process = NULL;
MyPCB pcb_table[MAXPROC];
char init_stack[USLOSS_MIN_STACK];
MyPCB ready_queues[7];


/******************************************
 ***  Functions to add/remove children  ***
 ******************************************/

/**
 * The function associates one process as a child of another process
 * @param parent a pointer to parent process control block
 * @param child a pointer child process control block
 */
void add_child(MyPCB *parent, MyPCB *child) {

    if (parent->first_child == NULL) {
        parent->first_child = child;
    } else {
        // add to the beginning of the list
        child->next_sibling = parent->first_child;
        parent->first_child->prev_sibling = child;
        parent->first_child = child;
    }
}

/**
 * This function stops associating one process as a child of a parent process.
 * @param parent a pointer to parent process control block
 * @param child a pointer to child process control block
 */
void remove_child(MyPCB *parent, MyPCB *child) {
    MyPCB *temp = NULL;

    // case 1: child that needs removing is the first in the list of children
    if (parent->first_child == child) {
        temp = parent->first_child;

        if (parent->first_child->next_sibling != NULL) {
            parent->first_child->next_sibling->prev_sibling = NULL;
        }
        parent->first_child = parent->first_child->next_sibling;

    } else // case2: not the first child
    {
        MyPCB *cur = parent->first_child;

        // find the child
        while (cur != child) {
            cur = cur->next_sibling;
        }

        temp = cur;

        cur->prev_sibling->next_sibling = cur->next_sibling;

        if (cur->next_sibling != NULL) {
            cur->next_sibling->prev_sibling = cur->prev_sibling;
        }
    }

    // clean up the next and prev pointers of the removed process
    temp->next_sibling = NULL;
    temp->prev_sibling = NULL;
}

/******************************************
 ***  Functions to manage ready queues ***
 ******************************************/

/**
 * Add to the the end of the queue
 * @param queue
 * @param element
 */
void add_to_queue(MyPCB *queue, MyPCB *element) {
    element->next_in_queue = queue->next_in_queue;
    queue->next_in_queue = element;
}

/**
 * The function adds process to one of the run queues based
 * on the process priority.
 * @param element pointer to a pcb
 */
void add_to_queues(MyPCB *element) {
    if (element == NULL) {
        printf("Cannot be null\n");
    }

    element->process_state = READY;
    MyPCB *queue = &ready_queues[element->process_priority];
    add_to_queue(queue, element);
}

/**
 * The function removes a process from the front of the queue.
 * @param queue a queue of runnable processes
 * @return a pointer to pcb
 */
MyPCB *remove_from_queue(MyPCB *queue) {

    MyPCB *cur = queue;
    MyPCB *prev = NULL;

    while (cur->next_in_queue != NULL) {
        prev = cur;
        cur = cur->next_in_queue;
    }

    prev->next_in_queue = NULL;

    return cur;
}

/**
 *The function removes a process with the highest priority from all run queues.
 * If no runnable process, return None.
 * @return a pointer to the highest priority queue
 */
MyPCB *remove_from_queues() {
    MyPCB *queue = NULL;

    for (int i = 1; i <= 6; i++) {
        if (ready_queues[i].next_in_queue != NULL) {
            queue = &ready_queues[i];
            break;
        }
    }

    return queue == NULL ? NULL : remove_from_queue(queue);
}

/**
 * The function returns a process from the front of the queue, without removing it.
 * @param queue a pointer to a queue of runnable processes.
 * @return a pointer to pcb
 */
MyPCB *peek_queue(MyPCB *queue) {

    MyPCB *cur = queue;

    while (cur->next_in_queue != NULL) {
        cur = cur->next_in_queue;
    }

    return cur;
}

/**
 *The function returns a process with the highest priority from all run queues, without removing it.
 * If no runnable process, return None.
 * @return a pointer to the highest priority queue
 */
MyPCB *peek_queues() {
    MyPCB *queue = NULL;

    for (int i = 1; i <= 6; i++) {

        if (ready_queues[i].next_in_queue != NULL) {
            queue = &ready_queues[i];
            break;
        }
    }

    return queue == NULL ? NULL : peek_queue(queue);
}

/**
 * Prints all run queues in pretty format for debugging purposes
 */
void dump_run_queues() {
    MyPCB *queue = NULL;

    for (int i = 1; i <= 6; i++) {

        if (ready_queues[i].next_in_queue != NULL) {
            USLOSS_Console("Priority %d: ", i);
            queue = &ready_queues[i];
            MyPCB *cur = queue->next_in_queue;

            while (cur != NULL) {
                USLOSS_Console("%d->", cur->process_id);
                cur = cur->next_in_queue;
            }

            USLOSS_Console("\n");
        }
    }
}

/******************************************
 ***  Functions to manage blocked queue  ***
 ******************************************/

/**
 * The function unblocks all process blocked on a certain process due to a particular reason.
 * @param process a process on which other process were blocked
 * @param block_reason release only processes whose reason for getting blocked is equal to this value
 */
void release_blocked_processes(MyPCB *process, enum BlockReason block_reason) {
    // release sequence of blocked process from the top of the block list
    while (process->next_in_block != NULL && process->next_in_block->block_reason == block_reason &&
           process->next_in_block->who_blocked == process->process_id) {
        add_to_queues(process->next_in_block);
        process->next_in_block = process->next_in_block->next_in_block;
    }

    if (process->next_in_block == NULL) return;

    MyPCB *prev = process->next_in_block;
    MyPCB *cur = process->next_in_block->next_in_block;

    while (cur != NULL) {
        if (cur->block_reason == block_reason && cur->who_blocked == process->process_id) {
            add_to_queues(cur);
            prev->next_in_block = cur->next_in_block;
            cur->next_in_block = NULL;
            cur = prev->next_in_block;
        } else {
            prev = cur;
            cur = cur->next_in_block;
        }
    }
}

/**
 * If a process A blocks on process B, add process A to the block-list of process B.
 * @param process a pointer to process which blocks
 * @param blockedProcess a pointer to process which is blocked
 */
void add_blocked_process(MyPCB *process, MyPCB *blockedProcess) {
    blockedProcess->who_blocked = process->process_id;

    if (process->next_in_block == NULL) {
        process->next_in_block = blockedProcess;
    } else {
        blockedProcess->next_in_block = process->next_in_block;
        process->next_in_block = blockedProcess;
    }
}

/**
 * Prints blocked process in pretty format for debug purposes.
 */
void dump_blocked_process() {
    MyPCB *process = NULL;

    for (int i = 0; i <= 50; i++) {
        process = &(pcb_table[i]);
        if (process->process_state != FREE) {
            USLOSS_Console("process %d: ", process->process_id);
            MyPCB *blocked = process->next_in_block;
            while (blocked) {
                USLOSS_Console("%d->", blocked->process_id);
                blocked = blocked->next_in_block;
            }
            USLOSS_Console("\n");
        }
    }
}


/******************************************
 *** Helper Functions                   ***
 ******************************************/

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
 * The functions finds the slot associated with a process.
 * Assume process with the given id is already in the table.
 * @param id if of the process
 * @return index of the process in the pcb table
 */
int get_slot(int id) {
    int slot = id % MAXPROC;
    int count = 0;

    // ensure process ids match, as a pcb is placed in the table through a linear-probing
    while (pcb_table[slot].process_id != id && count < MAXPROC) {
        slot = (slot + 1) % MAXPROC;
        count++;
    }

    return slot;
}

/**
 * Checks if a process with certain id exists
 * @param pid a pointer to the process to check for
 * @return 1 if exists. 0 otherwise
 */
int process_exists(int pid) {
    for (int i = 0; i < MAXPROC; i++) {
        if (pcb_table[i].process_id == pid && pcb_table[i].process_state != FREE) {
            return 1;
        }
    }

    return 0;
}

/**
 * The function assigns a lot for a given process id.
 * If not spot is available, assign -1
 * @param id process id
 * @return index of pcb in the table. -1 if a table is full.
 */
int request_slot(int id) {
    int potential_slot = id % MAXPROC;
    int count = 0;

    while (pcb_table[potential_slot].process_state != FREE && count < MAXPROC) {
        potential_slot = (potential_slot + 1) % MAXPROC;
        count++;
        // increment id, to match test output
        next_id++;
    }

    return count >= MAXPROC ? -1 : potential_slot;
}

/**
 * The function find the id of the first terminated child.
 * If none exists, returns -1
 * @return id of the dead child
 */
int find_dead_child() {
    MyPCB *cur = current_process->first_child;

    while (cur != NULL) {
        if (cur->process_state == TERM) {
            return cur->process_id;
        }

        cur = cur->next_sibling;
    }

    return -1;
}


/******************************************
 *** Functions to control interruptions ***
 ******************************************/

/**
 * The function verifies CPU is in kernel mode.
 * The simulation stops if the verification fails.
 */
void verify_kernel_mode(char *caller) {
    unsigned int psr = USLOSS_PsrGet();

    if (!(psr & USLOSS_PSR_CURRENT_MODE)) {
        char str[MAX_STATUS_LENGTH];
        snprintf(str, sizeof(str), "ERROR: Someone attempted to call %s while in user mode!",
                 caller);
        print_error(str, USER_MODE_ERROR);
    }
}

/**
 * The function disable interrupts.
 */
void disable_interrupts(char *caller) {
    verify_kernel_mode(caller);
    unsigned int oldPsr = USLOSS_PsrGet();
    unsigned int newPsr = oldPsr & ~USLOSS_PSR_CURRENT_INT;
    int result = USLOSS_PsrSet(newPsr);

    if (result != USLOSS_DEV_OK) {
        print_error("ERROR: Could not set PSR.", result);
    }
}

/**
 * The function enables interrupts.
 */
void enable_interrupt(char *caller) {
    verify_kernel_mode(caller);
    unsigned int psr = USLOSS_PsrGet();
    psr |= USLOSS_PSR_CURRENT_INT;
    int result = USLOSS_PsrSet(psr);

    if (result != USLOSS_DEV_OK) {
        print_error("ERROR: Could not set PSR.", result);
    }
}

/**
 * The function restores the pst to a given state.
 * @param oldPsr a psr state to restore to
 */
void restore_interrupts(unsigned int oldPsr, char *caller) {
    // to-do check if works
    verify_kernel_mode(caller);
    int result = USLOSS_PsrSet(oldPsr);

    if (result != USLOSS_DEV_OK) {
        print_error("ERROR: Could not set PSR.", result);
    }
}

/**
 * This is a wrapper function for process start functions.
 */
void wrapper(void) {
    enable_interrupt("start function");
    int status = current_process->start_func(current_process->args);
    quit(status);
}

/******************************************
 ***      API implementations           ***
 ******************************************/

/**
 * The function context switches from one process to another.
 * @param pid id of the process to switch to
 */
void dispatcher() {

    unsigned int psr = USLOSS_PsrGet();
    disable_interrupts("TEMP_switchTo");

    if (DEBUG) {
        USLOSS_Console("Entered dispatcher. %d\n", current_process == NULL ? -1 : current_process->process_id);
        dumpProcesses();
    }

    MyPCB *process_with_highest_priority = peek_queues();
    USLOSS_Context *old = NULL;
    USLOSS_Context *new = NULL;


    // case 1 no other runnable process, keep running
    if (process_with_highest_priority == NULL) {
        // keep running
    } else if (current_process == NULL) {
        remove_from_queues();
        current_process = process_with_highest_priority;
        current_process->process_state = RUNNING;
        current_process->run_start_time = currentTime();
        new = &(current_process->context);
        if (DEBUG) USLOSS_Console("Leaving dispatcher spot 1.\n");
        USLOSS_ContextSwitch(old, new);
    }
        //  case 2 current process terminated
    else if (current_process->process_state == TERM) {
        remove_from_queues();
        current_process = process_with_highest_priority;
        current_process->process_state = RUNNING;
        current_process->run_start_time = currentTime();
        new = &(current_process->context);
        if (DEBUG) USLOSS_Console("Leaving dispatcher spot 2. process %d will run now\n", current_process->process_id);
        USLOSS_ContextSwitch(old, new);
    }
        // case 3 current process is blocked and there
    else if (current_process->process_state == BLOCKED) {
        remove_from_queues();
        old = &(current_process->context);
        current_process->run_start_time = -1;

        current_process = process_with_highest_priority;
        current_process->process_state = RUNNING;
        current_process->run_start_time = currentTime();
        new = &(current_process->context);

        if (DEBUG) USLOSS_Console("Leaving dispatcher spot 3. process %d will run now\n", current_process->process_id);
        USLOSS_ContextSwitch(old, new);
    }
        // case 4 there is a process with higher priority
    else if ((process_with_highest_priority->process_priority < current_process->process_priority)) {
        old = &(current_process->context);

        remove_from_queues();
        //if the current process TERM or BLOCKED, it had to be caught earlier
        current_process->process_state = READY;
        current_process->run_start_time = -1;
        add_to_queues(current_process);

        current_process = process_with_highest_priority;
        current_process->process_state = RUNNING;
        current_process->run_start_time = currentTime();
        new = &(current_process->context);

        if (DEBUG) USLOSS_Console("Leaving dispatcher spot 4.\n");
        USLOSS_ContextSwitch(old, new);
    }
        // case 5 there is another process with the same priority and the current process has run for o>= 80 milliseconds.
    else if ((process_with_highest_priority->process_priority == current_process->process_priority &&
              (currentTime() - current_process->run_start_time) >= 80000)) {

        remove_from_queues();
        old = &(current_process->context);

        //move  the current process to ready queue if it is in running state
        if (current_process->process_state == RUNNING) {
            current_process->process_state = READY;
            current_process->run_start_time = -1;
            add_to_queues(current_process);
        }

        current_process = process_with_highest_priority;
        current_process->process_state = RUNNING;
        current_process->run_start_time = currentTime();
        new = &(current_process->context);
        if (DEBUG) USLOSS_Console("Leaving dispatcher spot 5.\n");
        USLOSS_ContextSwitch(old, new);
    }

    restore_interrupts(psr, "TEMP_switchTo");
}


/**
 * The starting process of the main process
 * @param arg Null
 */
int testcase_main_main(void *arg) {
    int status = testcase_main();

    if (status != 0) {
        USLOSS_Trace("Error: Testcase returned non-zero value.\n");
    }

    USLOSS_Halt(status);
    return status;
}

/**
* The start function for init process
* @param arg Null
* @return should never return
*/
int init_main(void *arg) {

    phase2_start_service_processes();
    phase3_start_service_processes();
    phase4_start_service_processes();
    phase5_start_service_processes();
    spork("testcase_main", &testcase_main_main, NULL, USLOSS_MIN_STACK, THREE);

    int status[1];

    while (1) {
        int val = join(status);

        if (val < 0) {
            print_error("ERROR: init had to run forever", val);
        }
    }
}

/**
* This function initializes your data structures,
* including setting up the process table entry for the
* starting process, init.
*/
void phase1_init(void) {
    // initialize pcb for init process
    int slot = request_slot(INIT_PROCESS_ID);
    MyPCB *init_process = &pcb_table[slot];
    init_process->process_id = INIT_PROCESS_ID;
    strcpy(init_process->name, "init");
    init_process->process_state = READY;
    init_process->process_priority = INIT_PRIORITY;
    init_process->stack = init_stack;
    init_process->start_func = &init_main;
    USLOSS_ContextInit(&(init_process->context), init_process->stack, USLOSS_MIN_STACK, NULL, &wrapper);
    add_to_queues(init_process);
}

/**
 * This function creates a new process, which is a child of the currently running process
 * @param name Stored in process table, useful for debug.
 * @param func The main() function for the child process.
 * @param arg The argument to pass to start_func(). May be NULL.
 * @param stacksize The size of the stack, in bytes. Must be no less than USLOSS_MIN_STACK
 * @param priority The priority of this process. Priority 6 is reserved for init, so the only valid values for this call are 1-5 (inclusive).
 * @return PID of child process. -2 if stackSize is less than USLOSS_MIN_STACK.
 * -1 if no empty slots in the process table, priority out of range,
 * start_func or name are NULL, name too long
 */
int spork(char *name, int(*func)(void *), void *arg, int stacksize, int priority) {
    unsigned int psr = USLOSS_PsrGet();
    disable_interrupts("spork");

    int slot = request_slot(next_id);

    if (stacksize < USLOSS_MIN_STACK) {
        restore_interrupts(psr, "spork");
        return -2;
    }

    // validate params
    if (slot == -1 || func == NULL || name == NULL || sizeof(name) > MAXNAME || priority < ONE || priority > FIVE) {
        restore_interrupts(psr, "spork");
        return -1;
    }

    MyPCB *newPCB = &pcb_table[slot];
    newPCB->process_id = next_id;
    next_id++;
    strcpy(newPCB->name, name);
    newPCB->process_priority = priority;
    newPCB->process_state = READY;
    newPCB->stack = malloc(USLOSS_MIN_STACK);
    newPCB->start_func = func;
    newPCB->args = arg;
    USLOSS_ContextInit(&(newPCB->context), newPCB->stack, USLOSS_MIN_STACK, NULL, &wrapper);

    // create parent-child association
    newPCB->parent = current_process;
    add_child(current_process, newPCB);
    add_to_queues(newPCB);

    dispatcher();
    restore_interrupts(psr, "spork");

    return newPCB->process_id;
}

/**
 * This function blocks the current process
 * until one of its children has terminated.
 * @param status the status of the child joined
 * @return id of the child joined
 */
int join(int *status) {
    unsigned int psr = USLOSS_PsrGet();
    disable_interrupts("join");

    if (status == NULL) {
        restore_interrupts(psr, "join");
        return -3;
    }

    if (current_process->first_child == NULL) {
        restore_interrupts(psr, "join");
        return -2;
    }

    // get the id of first dead child
    int dead_child_id = find_dead_child();
    // if not dead child, block
    while (dead_child_id == -1) {
        current_process->process_state = BLOCKED;
        current_process->block_reason = NO_DEAD_CHILD;
        dispatcher();
        dead_child_id = find_dead_child();
    }

    int dead_child_slot = get_slot(dead_child_id);
    MyPCB *dead_child = &pcb_table[dead_child_slot];
    *status = dead_child->exit_status;
    remove_child(current_process, dead_child);

    // mark dead child sport as free so a new process can take it
    dead_child->process_state = FREE;
    free(dead_child->stack);
    dead_child->stack = NULL;

    restore_interrupts(psr, "join");

    return dead_child_id;
}

/**
 * This function terminates the current process, with a certain “status” value.
 * A process should have no child.
 * @param status the status to terminate the process with
 */
void quit(int status) {

    unsigned int psr = USLOSS_PsrGet();
    disable_interrupts("quit");

    if (DEBUG) {
        USLOSS_Console("Quitting %d\n", current_process->process_id);
    }


    if (current_process->first_child != NULL) {
        char str[MAX_STATUS_LENGTH];
        snprintf(str, sizeof(str), "ERROR: Process pid %d called quit() while it still had children.",
                 current_process->process_id);
        print_error(str, USER_MODE_ERROR);
    }

    current_process->process_state = TERM;
    current_process->exit_status = status;

    // if parent was waiting to join a child, release a blocked parent
    if (current_process->parent->process_state == BLOCKED && current_process->parent->block_reason == NO_DEAD_CHILD) {
        add_to_queues(current_process->parent);
    }

    // wake up process that tried to zap this process
    release_blocked_processes(current_process, ZAP_INCOMPLETE_PROCESS);

    if (DEBUG) {
        USLOSS_Console("Quitting complete %d\n", current_process->process_id);
        dumpProcesses();
    }
    dispatcher();

    restore_interrupts(psr, "quit");
}

/**
 * This function makes an attempt to kill another process.
 * It always blocks as it can zap only ready or running process.
 * @param pid id of the process to zap
 */
void zap(int pid) {
    unsigned int psr = USLOSS_PsrGet();
    disable_interrupts("zap");

    if (DEBUG) {
        USLOSS_Console("%d is zapping %d\n", current_process->process_id, pid);
        dump_blocked_process();
    }

    char str[MAX_STATUS_LENGTH];

    if (process_exists(pid) == 0) {
        snprintf(str, sizeof(str), "ERROR: Attempt to zap() a non-existent process.");
        print_error(str, ERROR_STATE);
    }

    if (pid == INIT_PROCESS_ID) {
        snprintf(str, sizeof(str), "ERROR: Attempt to zap() init.");
        print_error(str, ERROR_STATE);
    }

    if (pid == current_process->process_id) {
        snprintf(str, sizeof(str), "ERROR: Attempt to zap() itself.");
        print_error(str, ERROR_STATE);
    }

    int slot = get_slot(pid);
    MyPCB *target_process = &pcb_table[slot];

    if (target_process->process_state == TERM) {
        snprintf(str, sizeof(str), "ERROR: Attempt to zap() a process that is already in the process of dying.");
        print_error(str, ERROR_STATE);
    }

    current_process->process_state = BLOCKED;
    current_process->block_reason = ZAP_INCOMPLETE_PROCESS;
    add_blocked_process(target_process, current_process);

    if (DEBUG) dump_blocked_process();

    dispatcher();
    restore_interrupts(psr, "zap");
}

/**
 * This functions get the id of the current process
 * @return id of the current process
 */
int getpid(void) {
    return current_process->process_id;
}

/**
 * Blocks the current process
 */
void blockMe(void) {
    unsigned int psr = USLOSS_PsrGet();
    disable_interrupts("blockMe");

    current_process->process_state = BLOCKED;
    current_process->block_reason = SELF_BLOCKED;
    dispatcher();

    restore_interrupts(psr, "blockMe");
}

/**
 * Check if the process exists and blocked.
 * @param pid
 * @return
 */
int unblockProc(int pid) {
    unsigned int psr = USLOSS_PsrGet();
    disable_interrupts("unblockProc");

    char str[MAX_STATUS_LENGTH];

    if (process_exists(pid) == 0) {
        snprintf(str, sizeof(str), "ERROR: Process pid %d does not exist.",
                 pid);
        print_error(str, ERROR_STATE);
    }

    int slot = get_slot(pid);
    MyPCB *target_process = &pcb_table[slot];

    // it must be blocked by blockMe.
    if (target_process->process_state != BLOCKED) {
        snprintf(str, sizeof(str), "ERROR: Process pid %d is not blocked",
                 pid);
        print_error(str, ERROR_STATE);
    }

    // process is blocked and reason is SELF_BLOCKED
    add_to_queues(target_process);
    dispatcher();

    restore_interrupts(psr, "unblockProc");
}

/**
 * Prints human-readable debug data about the process table.
 */
void dumpProcesses(void) {
    static const char *STATE_STRINGS[] = {"FREE", "Runnable", "Running", "Blocked", "Terminated"};
    static const char *BLOCK_REASON_STRINGS[] = {"None", "Blocked(waiting for child to quit)",
                                                 "Blocked(waiting for zap target to quit)", "Blocked(3)"};
    printf(" PID  PPID  NAME              PRIORITY  STATE\n");

    for (int i = 0; i < MAXPROC; i++) {
        const MyPCB *process = &pcb_table[i];

        // Skip empty slots, but include terminated processes
        if (process->process_state == FREE) {
            continue;
        }

        // use construct status field to match test output
        char status[MAX_STATUS_LENGTH];
        if (process->process_state == TERM) {
            snprintf(status, sizeof(status), "Terminated(%d)", process->exit_status);
        } else if (process->process_state == BLOCKED) {
            strncpy(status, BLOCK_REASON_STRINGS[process->block_reason], sizeof(status) - 1);
            status[sizeof(status) - 1] = '\0';  // Ensure null-termination
        } else {
            strncpy(status, STATE_STRINGS[process->process_state], sizeof(status) - 1);
            status[sizeof(status) - 1] = '\0';  // Ensure null-termination
        }


        USLOSS_Console("%4d  %4d  %-16s  %-8d  %s\n",
                       process->process_id,
                       process->parent ? process->parent->process_id : 0,
                       process->name,
                       process->process_priority,
                       status);
    }
}








