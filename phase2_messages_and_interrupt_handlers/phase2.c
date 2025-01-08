#include <stdio.h>
#include "phase2.h"
#include "phase1.h"
#include <string.h>

int mailbox_id = 0;
int slot_id = 0;
void (*systemCallVec[MAXSYSCALLS])(USLOSS_Sysargs *args);
int last_pump = 0;

#define DEBUG 0
#define MAX_STATUS_LENGTH 300
#define ERROR_CODE 1
#define MAILBOX_CLOCK 0
#define MAILBOX_DISK1 1
#define MAILBOX_DISK2 2
#define MAILBOX_TERMINAL1 3
#define MAILBOX_TERMINAL2 4
#define MAILBOX_TERMINAL3 5
#define MAILBOX_TERMINAL4 6
#define MICROSECOND_IN_MILLI 1000

typedef struct Slot Slot;
typedef struct MyPCB MyPCB;
typedef struct Mailbox Mailbox;

enum SlotState{
    SLOT_FREE,
    SLOT_ALLOCATED,
};

enum MailboxState{
    MAILBOX_FREE,
    BEING_RELEASED,
    MAILBOX_ALLOCATED,
};

enum ProcessState {
    PROC_FREE,
    PROC_ALLOCATED,
    MAILBOX_RELEASED,
};

struct Slot {
    char message[MAX_MESSAGE];
    Slot* next;
    enum SlotState status;
    int message_size;
};

struct MyPCB{
    int id;
    enum ProcessState status;
    MyPCB* next;
    char buffer[MAX_MESSAGE];
    int message_size;
    int max_message_size;
};

struct Mailbox{
    Slot slot_queue;
    MyPCB sender_queue;
    MyPCB receiver_queue;
    int slots_capacity;
    int slot_size;
    int available_slots;
    enum  MailboxState status;
    int id;
} ;

static MyPCB shadow_table[MAXPROC];
static Slot slot_table[MAXSLOTS];
static Mailbox mailbox_table[MAXMBOX];



/****
 * functions to manager process queues
 */

int is_process_queue_empty(MyPCB* queue){
    if (queue->next == NULL) return 1;
    else return 0;
}



MyPCB* remove_from_process_queue(MyPCB* queue){
    if (is_process_queue_empty(queue)) return NULL;

    MyPCB *cur = queue;
    MyPCB *prev = NULL;

    while (cur->next != NULL) {
        prev = cur;
        cur = cur->next;
    }

    prev->next = NULL;
    return cur;
}

void add_to_process_queue(MyPCB* queue, MyPCB* element){
    element->next = queue->next;
    queue->next = element;
}

/**
 * Operations to manage slot queue
 */

int is_slot_queue_empty(Slot* queue){
    if (queue->next == NULL) return 1;
    else return 0;
}

/**
 * Remove the slot from the slot queue
 * @param mailbox
 * @return
 */
Slot* remove_from_slot_queue(Mailbox* mailbox){
    Slot* queue = &(mailbox->slot_queue);
    if (is_slot_queue_empty(queue)) return NULL;

    Slot *cur = queue;
    Slot *prev = NULL;

    while (cur->next != NULL) {
        prev = cur;
        cur = cur->next;
    }

    prev->next = NULL;
    mailbox->available_slots ++;

    return cur;
}

void add_to_slot_queue(Mailbox* mailbox, Slot* element){
    Slot* queue = &(mailbox->slot_queue);
    element->next = queue->next;
    queue->next = element;
    mailbox->available_slots -- ;
}

int request_slot_id(){
    int potential_id = slot_id % MAXSLOTS;
    int count = 0;

    while (slot_table[potential_id].status != SLOT_FREE && count < MAXSLOTS){
        potential_id = (potential_id + 1) % MAXSLOTS;
        count ++;
    }

    return count >= MAXSLOTS ? -1 : potential_id;
}

Slot* get_free_slot(){
    int free_slot_id = request_slot_id();
    if (free_slot_id == -1) return NULL;
    Slot* slot = &slot_table[free_slot_id];
    slot->status = SLOT_ALLOCATED;
    slot_id ++;
    return slot;
}

int request_mailbox_id(){
    int potential_id = mailbox_id % MAXMBOX;
    int count = 0;

    while (mailbox_table[potential_id].status != MAILBOX_FREE && count < MAXMBOX){
        potential_id = (potential_id + 1) % MAXMBOX;
        count ++;
    }

    return count >= MAXMBOX ? -1 : potential_id;
}

Mailbox* get_free_mailbox(){
    int free_mailbox_id = request_mailbox_id();

    if(free_mailbox_id == -1) return NULL;

    Mailbox* mailbox = &mailbox_table[free_mailbox_id];
    mailbox->status = MAILBOX_ALLOCATED;
    mailbox->id = free_mailbox_id;
    mailbox_id++;

    return mailbox;
}


MyPCB* get_process() {
    int id = getpid();
    int allocated_slot = id % MAXPROC;
    MyPCB *process = &shadow_table[allocated_slot];
    process->id = id;
    process->status = PROC_ALLOCATED;
    return process;
}

int pointer_checker(void* pointer, int error_code){
    if (pointer == NULL) {
        if(DEBUG) USLOSS_Console("Null pointer\n");
        return error_code;
    }

    return 1;
}

void my_copy(void* source, void* dest, int size){
    if (pointer_checker(source, -1) == 1 && pointer_checker(dest, -1)==1){
        memcpy(source, dest, size);
    }
}

void dump_slots(Mailbox* mailbox){
    Slot* cur = mailbox->slot_queue.next;

    while (cur){
        USLOSS_Console("message %s ->", cur->message);
        cur = cur->next;
    }

    USLOSS_Console("\n");
}

void dump_mapboxes(){
    Mailbox * box =NULL;
    for (int i=0; i< MAXMBOX; i++){
        box = &mailbox_table[i];
        if (box->status != MAILBOX_FREE){
            USLOSS_Console("id %d status %d\n", i, box->status);
        }
    }
}

void dump_queue(MyPCB* queue){

    MyPCB * cur = queue->next;

    while (cur != NULL){
        USLOSS_Console("id %d -> ",cur->id);
        cur = cur->next;
    }

    USLOSS_Console("\n");

}

int mailbox_exists(int id){
    if (id < MAXMBOX && id >= 0 && mailbox_table[id].status == MAILBOX_ALLOCATED){
        return 1;
    }

    return 0;
}

void unblock_consumer_producer(MyPCB* queue){
    if (!is_process_queue_empty(queue)){
        MyPCB* blocked_process = remove_from_process_queue(queue);
        unblockProc(blocked_process->id);
    }
}

void unblock_receiver(MyPCB* queue, Mailbox* mailbox){

    if (!is_process_queue_empty(queue)){
        MyPCB* blocked_process = remove_from_process_queue(queue);
        Slot* slot = remove_from_slot_queue(mailbox);
        // to do check if it can fit
        my_copy(blocked_process->buffer, slot->message, slot->message_size);
        blocked_process->message_size = slot->message_size;
        unblockProc(blocked_process->id);
    }
}

void unblock_sender(Mailbox* mailbox){
    MyPCB * queue = &mailbox->sender_queue;
    if (!is_process_queue_empty(queue)){
        MyPCB* blocked_sender = remove_from_process_queue(queue);
        Slot * slot = get_free_slot();
        my_copy(slot->message, blocked_sender->buffer, blocked_sender->message_size);
        slot->message_size = blocked_sender->message_size;
        add_to_slot_queue(mailbox, slot);
        unblockProc(blocked_sender->id);
    }
}

void free_slots(Slot* slot_queue){
    if (DEBUG) USLOSS_Console("free slots began\n");
    Slot* cur = slot_queue->next;
    Slot* temp = NULL;

    while (cur){
        temp = cur;
        cur = cur->next;
        temp->status = SLOT_FREE;
    }

    if (DEBUG) USLOSS_Console("free slots ended\n");
}

void release_processes(MyPCB* queue){
    if (!is_process_queue_empty((queue)) ){
        MyPCB* removed_process = remove_from_process_queue(queue);
        removed_process->status = MAILBOX_RELEASED;
        unblockProc(removed_process->id);
    }
}

/******************************************
 *** Functions to control interruptions ***
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
 * The function verifies CPU is in kernel mode.
 * The simulation stops if the verification fails.
 */
void verify_kernel_mode(char *caller) {
    unsigned int psr = USLOSS_PsrGet();

    if (!(psr & USLOSS_PSR_CURRENT_MODE)) {
        char str[MAX_STATUS_LENGTH];
        snprintf(str, sizeof(str), "ERROR: Someone attempted to call %s while in user mode!",
                 caller);
        print_error(str, ERROR_CODE);
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
 * The function restores the pst to a given state.
 * @param oldPsr a psr state to restore to
 */
void restore_interrupts(unsigned int oldPsr, char *caller) {
    // to-do check it works
    verify_kernel_mode(caller);
    int result = USLOSS_PsrSet(oldPsr);

    if (result != USLOSS_DEV_OK) {
        print_error("ERROR: Could not set PSR.", result);
    }
}


int MboxCreate(int slots, int slot_size){
    unsigned int psr = USLOSS_PsrGet();
    disable_interrupts("MaxCreate");

    if (slots < 0 || slot_size < 0 || slots > MAXSLOTS || slot_size > MAX_MESSAGE){
        restore_interrupts(psr, "spork");
        return -1;
    }

    Mailbox* mailbox = get_free_mailbox();
    if (mailbox == NULL){
        restore_interrupts(psr, "spork");
        return -1;
    }
    mailbox->slot_size = slot_size;
    mailbox->available_slots = slots;
    mailbox->slots_capacity = slots;

    restore_interrupts(psr, "spork");
    return mailbox->id;
}


int MboxRelease(int mailboxId){
    unsigned int psr = USLOSS_PsrGet();
    disable_interrupts("MboxRelease");


    Mailbox *mailbox = &mailbox_table[mailboxId];
    mailbox->status = BEING_RELEASED;
    free_slots(&mailbox->slot_queue);
    if (!is_process_queue_empty(&(mailbox->receiver_queue))){
        release_processes(&mailbox->receiver_queue);
    }
    if (!is_process_queue_empty(&(mailbox->sender_queue))){
        release_processes(&mailbox->sender_queue);
    }
    mailbox->status = MAILBOX_FREE;
    restore_interrupts(psr, "MboxRelease");
    return 0;
}


int handle_zero_slot_send(void *msg_ptr, int msg_size, Mailbox *mailbox, MyPCB *sender, int cond) {// if receive is not waiting
    unsigned int psr = USLOSS_PsrGet();
    disable_interrupts("MboxSendRoot");

    if(DEBUG) USLOSS_Console("zero slot send enter 1\n");

    if (is_process_queue_empty(&mailbox->receiver_queue)){
        if (cond) return -2;
        add_to_process_queue(&mailbox->sender_queue, sender);
        blockMe();
        if (sender->status == MAILBOX_RELEASED){
            release_processes(&mailbox->sender_queue);
            return -1;
        }

    } else{
        if(DEBUG) USLOSS_Console("zero slot send enter 2\n");
        MyPCB* receiver = remove_from_process_queue(&mailbox->receiver_queue);
        my_copy(receiver->buffer, msg_ptr, msg_size);
        receiver->message_size = msg_size;
        unblockProc(receiver->id);
    }

    restore_interrupts(psr, "MboxSendRoot");
    return 0;
}



int MboxSendRoot(int mbox_id, void *msg_ptr, int msg_size, int cond){

    unsigned int psr = USLOSS_PsrGet();
    disable_interrupts("MboxSendRoot");

    if (DEBUG){
        USLOSS_Console("Sending to %d\n", mbox_id);
    }

    Mailbox* mailbox = &mailbox_table[mbox_id];
    MyPCB *sender = get_process();
    sender->message_size = msg_size;
    my_copy(sender->buffer, msg_ptr, msg_size);

    if (!mailbox_exists(mbox_id) || mailbox->slot_size < msg_size){
        return -1;
    }
    if (mailbox->slots_capacity == 0){
        return handle_zero_slot_send(msg_ptr, msg_size, mailbox, sender, cond);
    }

    // deal with slots_capacity, only if it is nonzero slot mailbox
    Slot* slot = get_free_slot();
    if (pointer_checker(slot, -2)==-2){
        return -2;
    }


    my_copy(slot->message, msg_ptr, msg_size);
    slot->message_size = msg_size;
    if (DEBUG) USLOSS_Console("Set slot size to %d\n", slot->message_size);

    if (mailbox->available_slots <= 0) {

        if (cond) {
            slot->status = SLOT_FREE;
            return -2;
        }

        add_to_process_queue(&mailbox->sender_queue, sender);
        blockMe();
        slot->status = SLOT_FREE;
        if (sender->status == MAILBOX_RELEASED) {
            release_processes(&mailbox->sender_queue);
            return -1;
        }
        return 0;
    }


    add_to_slot_queue(mailbox, slot);
    // unblock one receiver so that they can use freed slot
    unblock_receiver(&mailbox->receiver_queue, mailbox);
    restore_interrupts(psr, "MboxSendRoot");

    return 0;
}

int handle_zero_slot_receive(void *msg_ptr, int msg_max_size, Mailbox *mailbox, MyPCB *receiver, int cond) {
    if(DEBUG) USLOSS_Console("zero slot receive enter 0\n");
    if (is_process_queue_empty(&mailbox->sender_queue)){
        if(DEBUG) USLOSS_Console("zero slot receive enter 1\n");
        if (cond) return -2;
        add_to_process_queue(&mailbox->receiver_queue, receiver);
        blockMe();
        if (receiver->status==MAILBOX_RELEASED){
            release_processes(&mailbox->receiver_queue);
            return -1;
        }
        return receiver->message_size;
    } else {
        if(DEBUG) USLOSS_Console("zero slot receive enter 2\n");
        MyPCB* sender = remove_from_process_queue(&mailbox->sender_queue);

        if ( sender->message_size > receiver->message_size){
            return -1;
        }

        my_copy(msg_ptr, sender->buffer, sender->message_size);
        unblockProc(sender->id);
        return sender->message_size;
    }
    // to-do return the size of the message
}

int MboxRecvRoot(int mbox_id, void *msg_ptr, int msg_max_size, int cond){
    unsigned int psr = USLOSS_PsrGet();
    disable_interrupts("MboxRecvRoot");

    if(DEBUG){
        USLOSS_Console("Receiving\n");
    }

    Mailbox* mailbox = &mailbox_table[mbox_id];
    MyPCB *receiver = get_process();
    receiver->max_message_size = msg_max_size;

    if (!mailbox_exists(mbox_id))
        return -1;

    // handle a zero-slot mailbox
    if (mailbox->slots_capacity == 0){
        return handle_zero_slot_receive(msg_ptr, msg_max_size, mailbox, receiver, cond);
    }

    if (is_slot_queue_empty(&mailbox->slot_queue)){
        if (cond) return -2;
        add_to_process_queue(&mailbox->receiver_queue, receiver);
        blockMe();
        if (DEBUG){
            USLOSS_Console("Receiving %s\n", receiver->buffer);
        }
        if (receiver->status == MAILBOX_RELEASED){
            release_processes(&mailbox->receiver_queue);
            return -1;
        }

        if (receiver->message_size > msg_max_size ){
            return -1;
        }

        my_copy(msg_ptr, receiver->buffer, receiver->message_size);
        restore_interrupts(psr, "MboxRecvRoot");
        return receiver->message_size;
    }


    Slot* slot = remove_from_slot_queue(mailbox);
    slot->status =  SLOT_FREE;
    if (slot->message_size > msg_max_size) return -1;
    my_copy(msg_ptr, slot->message, slot->message_size);
    unblock_sender(mailbox);
    restore_interrupts(psr, "MboxRecvRoot");
    return slot->message_size;
}

int MboxSend(int mbox_id, void *msg_ptr, int msg_size){
    return MboxSendRoot(mbox_id, msg_ptr, msg_size, 0);
}

int MboxCondSend(int mbox_id, void *msg_ptr, int msg_size){
    return MboxSendRoot(mbox_id, msg_ptr, msg_size, 1);
}

int MboxRecv(int mbox_id, void *msg_ptr, int msg_max_size){
    return MboxRecvRoot(mbox_id, msg_ptr, msg_max_size, 0);
}

int MboxCondRecv(int mbox_id, void *msg_ptr, int msg_max_size){
    return MboxRecvRoot(mbox_id, msg_ptr, msg_max_size, 1);
}


void waitDevice(int type, int unit, int *status){
    unsigned int psr = USLOSS_PsrGet();
    disable_interrupts("waitDevice");

    if (type == USLOSS_CLOCK_DEV){
        MboxRecv(MAILBOX_CLOCK, status, sizeof (int));
    } else if (type == USLOSS_DISK_DEV){
        if (unit == 0){
            MboxRecv(MAILBOX_DISK1, status, sizeof (int ));
        } else if (unit == 1){
            MboxRecv(MAILBOX_DISK2, status, sizeof(int));
        } else{
            print_error("Error: wrong unit", ERROR_CODE);
        }
    } else if (type == USLOSS_TERM_DEV){
        if (unit == 0){
            MboxRecv(MAILBOX_TERMINAL1, status, sizeof (int));
        } else if (unit == 1){
            MboxRecv(MAILBOX_TERMINAL2, status, sizeof (int));
        } else if (unit == 2){
            MboxRecv(MAILBOX_TERMINAL3, status, sizeof (int));
        } else if (unit == 3){
            MboxRecv(MAILBOX_TERMINAL4, status, sizeof (int));
        } else {
            print_error("Error: wrong unit", ERROR_CODE);
        }
    } else{
        print_error("Error: wrong unit", ERROR_CODE);
    }

    restore_interrupts(psr, "waitDevice");

}

void wakeupByDevice(int type, int unit, int status){

}

void clock_handler(int dev, void* args){
    unsigned int psr = USLOSS_PsrGet();
    disable_interrupts("clock_handler");

    int result = currentTime();
    if (currentTime() - last_pump >= (100*MICROSECOND_IN_MILLI)){
        last_pump = result;
        MboxCondSend(MAILBOX_CLOCK, &result, sizeof (int));
        dispatcher();
    }

    restore_interrupts(psr, "clock_handler");
}

void disk_handler(int dev, void* args){
    unsigned int psr = USLOSS_PsrGet();
    disable_interrupts("clock_handler");

    int unit;
    int status;
    int result;

    unit = (int)(long)args;
    result = USLOSS_DeviceInput(USLOSS_TERM_DEV, unit, &status);
    if (result != USLOSS_DEV_OK) {
        USLOSS_Console("Error: Could not read terminal device status.\n");
        USLOSS_Halt(1);
    }

    if (unit == 0){
        MboxCondSend(MAILBOX_DISK1, &status, sizeof (int));
    } else{
        MboxCondSend(MAILBOX_DISK2, &status, sizeof (int));
    }

    restore_interrupts(psr, "clock_handler");
}

void terminal_handler(int dev, void* args){
    int unit = 0;
    int status = 0;
    int result = 0;

    unit = (int)(long)args;
    result = USLOSS_DeviceInput(USLOSS_TERM_DEV, unit, &status);

    if (result != USLOSS_DEV_OK) {
        USLOSS_Console("Error: Could not read terminal device status.\n");
        USLOSS_Halt(1);
    }

    if (unit == 0){
        MboxCondSend(MAILBOX_TERMINAL1, &status, sizeof (int));
    } else if (unit == 1){
        MboxCondSend(MAILBOX_TERMINAL2, &status, sizeof (int));
    } else if (unit == 2){
        MboxCondSend(MAILBOX_TERMINAL3, &status, sizeof (int));
    } else if (unit == 3){
        MboxCondSend(MAILBOX_TERMINAL4, &status, sizeof (int));
    }
}

void nullsys ( USLOSS_Sysargs* args){
    char str[MAX_STATUS_LENGTH];

    int sys_call = ((USLOSS_Sysargs*)(args))->number;
    if (sys_call < 50){
        snprintf(str, sizeof(str), "nullsys(): Program called an unimplemented syscall.  syscall no: %d   PSR: 0x09", sys_call);
    } else {
        snprintf(str, sizeof(str), "syscallHandler(): Invalid syscall number %d", sys_call);
    }

    print_error(str, ERROR_CODE);
}

void systemcall_handler ( int dev , void* args){
    char str[MAX_STATUS_LENGTH];

    int sys_call = ((USLOSS_Sysargs*)(args))->number;
    if (sys_call < 50){
        snprintf(str, sizeof(str), "nullsys(): Program called an unimplemented syscall.  syscall no: %d   PSR: 0x09", sys_call);
    } else {
        snprintf(str, sizeof(str), "syscallHandler(): Invalid syscall number %d", sys_call);
    }

    print_error(str, ERROR_CODE);
}



void phase2_init(void){
    for (int i =0; i <= MAILBOX_TERMINAL4; i++){
        MboxCreate(1, MAX_MESSAGE);
    }

    for (int i=0; i < MAXSYSCALLS; i++){
        systemCallVec[i] =  nullsys;
    }

    USLOSS_IntVec[USLOSS_CLOCK_INT] = clock_handler;
    USLOSS_IntVec[USLOSS_TERM_INT] = terminal_handler;
    USLOSS_IntVec[USLOSS_DISK_INT] = disk_handler;
    USLOSS_IntVec[USLOSS_SYSCALL_INT] = systemcall_handler;
}

void phase2_start_service_processes(void){
    return;
}

