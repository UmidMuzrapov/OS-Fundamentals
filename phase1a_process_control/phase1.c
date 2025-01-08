/**
* @author Umid Muzrapov
     * Course: CS452
     * Phase 1 a
     * Instructor: Russell Lewis
     * TA: Priya Kaushik, Junyong Zhao
     * Due Date: Oct 2
 *
* Description: The program implements a number of functions for the first phase of the project:
     * phase1_init
     * spork
     * join
     * quit_phase_1a
     * quit
     * getpid
     * dumpProcess
     * TEMP_switchTo
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

typedef struct MyPCB MyPCB;

struct MyPCB {
    int process_id;
    int exit_status;
    char name[MAXNAME];
    MyPCB *first_child;
    MyPCB *parent;
    MyPCB *next_sibling;
    MyPCB *prev_sibling;
    enum ProcessState process_state;
    enum ProcessPriority process_priority;
    void *stack;

    int (*start_func)(void *);

    void *args;
    USLOSS_Context context;
};

#define INIT_PRIORITY 6
#define INIT_PROCESS_ID 1
#define USER_MODE_ERROR 1
#define MAX_STATUS_LENGTH 300

int next_id = 2;
MyPCB *current_process = NULL;
MyPCB pcb_table[MAXPROC];
char init_stack[USLOSS_MIN_STACK];


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
 *** Helper Functions                   ***
 ******************************************/

/**
 * Prints error message and halts.
 * @param str
 * @param code
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

/******************************************
 *** Functions to control interruptions ***
 ******************************************/

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
 ***      API implementations           ***
 ******************************************/

/**
 * The starting process of the main process
 * @param arg Null
 */
int testcase_main_main(void *arg) {
    int status = testcase_main();

    if (status != 0) {
        USLOSS_Trace("Error: Testcase returned non-zero value.\n");
    }

    USLOSS_Trace("Phase 1A TEMPORARY HACK: testcase_main() returned, simulation will now halt.\n");
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
    USLOSS_Console(
            "Phase 1A TEMPORARY HACK: init() manually switching to testcase_main() after using spork() to create it.\n");
    int main_process_id = spork("testcase_main", &testcase_main_main, NULL, USLOSS_MIN_STACK, THREE);
    TEMP_switchTo(main_process_id);

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

    // initialize a pcb for a new process
    MyPCB *newPCB = &pcb_table[slot];
    newPCB->process_id = next_id;
    next_id++;
    strcpy(newPCB->name, name);
    //newPCB.parent = currentPID;
    newPCB->process_priority = priority;
    newPCB->process_state = READY;
    newPCB->stack = malloc(USLOSS_MIN_STACK);
    newPCB->start_func = func;
    newPCB->args = arg;
    USLOSS_ContextInit(&(newPCB->context), newPCB->stack, USLOSS_MIN_STACK, NULL, &wrapper);

    // create parent-child association
    newPCB->parent = current_process;
    add_child(current_process, newPCB);
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

    // if no child, return -2
    if (current_process->first_child == NULL) {
        restore_interrupts(psr, "join");
        return -2;
    }

    // get the id of first dead child
    int dead_child_id = find_dead_child();

    // if not dead child, block. Will not happen in phase 1 a
    if (dead_child_id == -1) {
        // will block
    }

    int dead_child_slot = get_slot(dead_child_id);
    MyPCB *dead_child = &pcb_table[dead_child_slot];
    *status = dead_child->exit_status;
    remove_child(current_process, dead_child);
    // mark dead child sport as free so a new process can take it
    dead_child->process_state = FREE;
    free(dead_child->stack);

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

    if (current_process->first_child != NULL) {
        char str[MAX_STATUS_LENGTH];
        snprintf(str, sizeof(str), "ERROR: Process pid %d called quit() while it still had children.",
                 current_process->process_id);
        print_error(str, USER_MODE_ERROR);
    }

    current_process->process_state = TERM;
    current_process->exit_status = status;

    restore_interrupts(psr, "quit");
}

/**
 * This is a hacky quit for phase 1a.
 * @param status the status to terminate the process with
 * @param switchToPid id of the process to context switch to
 */
void quit_phase_1a(int status, int switchToPid) {
    unsigned int psr = USLOSS_PsrGet();
    disable_interrupts("quit_phase_1a");

    if (current_process->first_child != NULL) {
        char str[MAX_STATUS_LENGTH];
        snprintf(str, sizeof(str), "ERROR: Process pid %d called quit() while it still had children.",
                 current_process->process_id);
        print_error(str, USER_MODE_ERROR);
    }

    current_process->process_state = TERM;
    current_process->exit_status = status;

    TEMP_switchTo(switchToPid);
    restore_interrupts(psr, "quit_phase_1a");
}

/**
 * This functions get the id of the current process
 * @return id of the current process
 */
int getpid(void) {
    return current_process->process_id;
}

/**
 * Prints human-readable debug data about the process table.
 */
void dumpProcesses(void) {
    static const char *STATE_STRINGS[] = {"FREE", "Runnable", "Running", "Blocked", "Terminated"};
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

/**
 * The function context switches from one process to another for phase1 a.
 * @param pid if of the process to switch to
 */
void TEMP_switchTo(int pid) {
    unsigned int psr = USLOSS_PsrGet();
    disable_interrupts("TEMP_switchTo");

    USLOSS_Context *oldP = NULL;
    USLOSS_Context *newP = &(pcb_table[get_slot(pid)].context);

    // if not the first process being created
    if (current_process != NULL) {
        oldP = &(current_process->context);
        current_process->process_state =
                current_process->process_state == RUNNING ? READY : current_process->process_state;
    }

    current_process = &(pcb_table[get_slot(pid)]);
    current_process->process_state = RUNNING;

    USLOSS_ContextSwitch(oldP, newP);
    restore_interrupts(psr, "TEMP_switchTo");
}





