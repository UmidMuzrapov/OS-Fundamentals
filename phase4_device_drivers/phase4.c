/**
* @author Umid Muzrapov
     * Course: CS452
     * Phase 4  - Device Drivers
     * Instructor: Russell Lewis
     * TA: Priya Kaushik, Junyong Zhao
     * Due Date: Dec 11
*
 * Operational Requirements:
     *  C99
     *  stdlib
     *  string
     *  stdio
     *  phase1.h
     *  phase2.h
     *  phase3.h
     *  phase4.h
     *  usoloss
     *  usyscall.h
     *  phase3_usermode.h
     *  phase4_usemode.h
     *  phase3_kernelInterfaces.h
     *
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
#include <string.h>
#include "phase3_kernelInterfaces.h"

#define MAX_PROC_PRIORITY 1
#define MICROSECOND_IN_MILLI 1000
#define MILLI_IN_SECOND 1000
#define TERMINAL_UNITS 4
#define DISK_UNITS 2
#define BLOCKS_IN_DISK 16
#define BYTES_IN_BLOCK 512
#define DEBUG 0

typedef struct Mutex Mutex;
typedef struct MyPCB MyPCB;
typedef struct QueueManager QueueManager;
typedef struct TerminalControl TerminalControl;
typedef struct DiskControl DiskControl;
typedef struct DiskSize DiskSize;
typedef struct DiskRequest DiskRequest;
typedef struct DiskResponse DiskResponse;

struct Mutex {
    int mailbox_id;
};

enum DiskRequestType {
    READ,
    WRITE
};

struct DiskSize {
    int tracks;
    int initialized;
};

struct DiskRequest {
    int track;
    int first_block;
    int blocks;
    enum DiskRequestType type;
};

struct DiskResponse {
    int status;
};

struct MyPCB {
    int id;
    MyPCB *next;
    char buffer_write[MAX_MESSAGE];
    int buffer_size_write;
    int write_count;
    int sleep_start;
    int sleep_duration;
    DiskRequest disk_request;
    DiskResponse diskResponse;
    char disk_buffer[BLOCKS_IN_DISK * BYTES_IN_BLOCK];
};

struct TerminalControl {
    Mutex write_lock;
    int read_mailbox_id;
    MyPCB *writing_proc;
    MyPCB writing_queue;
    char read_buffer[MAXLINE + 1];
    int read_buffer_count;
};

struct DiskControl {
    Mutex tracks_lock;
    //int read_write_mailbox_id;
    Mutex read_write_lock;
    DiskSize disk_size;
    char *disk_buffer;
    MyPCB write_read_queue;
    int last_track;
    int sem_id;
};

struct QueueManager {
    MyPCB clock_queue;
};

static TerminalControl terminal_controls[TERMINAL_UNITS];
static DiskControl disk_controls[DISK_UNITS];
static TerminalControl terminal_controls[TERMINAL_UNITS];
static Mutex global_lock;
static MyPCB shadow_table[MAXPROC];
static QueueManager queue_manager;

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
void gain_lock(Mutex *lock) {
    int result = MboxSend(lock->mailbox_id, NULL, 0);
    if (result != 0) print_error("Error: could not gain lock.", -1);
}

/**
 * The function releases the global lock
 */
void release_lock(Mutex *lock) {
    int result = MboxRecv(lock->mailbox_id, NULL, 0);
    if (result < 0) print_error("Error: could not release lock.", -1);
}

/****************************************
 * Functions to manage process queue
 ***************************************/

/**
 * The function checks if a process queue is empty
 * @param queue
 * @return 1 if empty. 0 otherwise
 */
int is_process_queue_empty(MyPCB *queue) {
    if (queue->next == NULL) return 1;
    else return 0;
}

/**
 * The functions removed from the top of the queue
 * @param queue
 * @return Null if empty. Top process otherwise.
 */
MyPCB *remove_from_process_queue(MyPCB *queue) {
    gain_lock(&global_lock);

    if (is_process_queue_empty(queue)) {
        release_lock(&global_lock);
        return NULL;
    }

    MyPCB *cur = queue;
    MyPCB *prev = NULL;

    while (cur->next != NULL) {
        prev = cur;
        cur = cur->next;
    }

    prev->next = NULL;
    release_lock(&global_lock);
    return cur;
}

/**
 * The function removes a given process from the queue
 * @param queue a queue of processes
 * @param element a process to remove
 */
void remove_specific_proc(MyPCB *queue, MyPCB *element) {
    gain_lock(&global_lock);

    if (is_process_queue_empty(queue)) {
        release_lock(&global_lock);
        return;
    }

    MyPCB *cur = queue->next; // Start from the first element in the queue
    MyPCB *prev = queue;      // Keep track of the previous element

    while (cur != NULL) {
        if (cur == element) { // Found the element to remove
            prev->next = cur->next; // Bypass the element
            cur->next = NULL;
            release_lock(&global_lock);// Clean up the removed element's pointer (optional)
            return;
        }
        prev = cur; // Move forward in the queue
        cur = cur->next;
    }

    release_lock(&global_lock);

}

/**
 * The function add to the end of the queue
 * @param queue a queue of processes
 * @param element process to add to the queue
 */
void add_to_process_queue(MyPCB *queue, MyPCB *element) {
    gain_lock(&global_lock);
    element->next = queue->next;
    queue->next = element;
    release_lock(&global_lock);
}

/**
 * Remove a process from the queue based on track number
 * @param queue queue of processes
 * @param prev_track previous track number to compare against
 * @return Removed process or NULL if no suitable process found
 */
MyPCB *remove_from_process_queue_elevator(MyPCB *queue, int prev_track) {
    gain_lock(&global_lock);

    //dump_queue(queue);
    // If queue is empty
    if (is_process_queue_empty(queue)) {
        release_lock(&global_lock);
        return NULL;
    }

    if (prev_track == -1) {
        release_lock(&global_lock);
        return remove_from_process_queue(queue);
    }

    MyPCB *cur = queue->next;
    MyPCB *prev = queue;
    MyPCB *target = NULL;
    MyPCB *target_prev = NULL;

    // First pass: find a process with track > prev_track
    while (cur != NULL) {
        if (cur->disk_request.track > prev_track) {
            target = cur;
            target_prev = prev;
            break;
        }
        prev = cur;
        cur = cur->next;
    }

    // If no process found with track > prev_track,
    // find the process with the lowest track number
    if (target == NULL) {
        cur = queue->next;
        prev = queue;
        target = cur;
        target_prev = prev;

        while (cur != NULL) {
            if (cur->disk_request.track < target->disk_request.track) {
                target = cur;
                target_prev = prev;
            }
            prev = cur;
            cur = cur->next;
        }
    }

    // Remove the target process from the queue
    if (target != NULL) {
        target_prev->next = target->next;
        target->next = NULL;
    }

    release_lock(&global_lock);
    return target;
}

/**
 * The function gets a free process
 * @return
 */
MyPCB *get_process() {
    int id = getpid();
    int allocated_slot = id % MAXPROC;
    MyPCB *process = &shadow_table[allocated_slot];
    process->id = id;
    return process;
}


/**************System call handlers *************/

/**
 * This is the handler for sleep system call.
 * @param args
 */
void system_sleep_handler(USLOSS_Sysargs *args) {
    MyPCB *process = get_process();
    int sleep_duration = (int) (long) args->arg1;

    // a negative duration is not valid
    if (sleep_duration < 0) {
        args->arg4 = (void *) (long) (-1);
        return;
    }

    // note sleep and asked wake-up time
    process->sleep_start = currentTime();
    process->sleep_duration = sleep_duration * MICROSECOND_IN_MILLI * MILLI_IN_SECOND;
    add_to_process_queue(&queue_manager.clock_queue, process);
    // sleep until the daemon wakes me up
    blockMe();
    args->arg4 = (void *) (long) (0);
}

/**
 * This is the handler for terminal read system call.
 *
 * @param args
 */
void system_termread_handler(USLOSS_Sysargs *args) {
    char *buffer = (char *) args->arg1;
    int buffer_size = (int) (long) args->arg2;
    int unit_id = (int) (long) args->arg3;

    // check for invalid arguments
    if (buffer_size <= 0 || unit_id < 0 || unit_id >= TERMINAL_UNITS) {
        args->arg4 = (void *) (long) (-1);
        args->arg2 = (void *) (long) (0);
        return;
    }

    // receive the message from the correct terminal unit
    int received_size = MboxRecv(terminal_controls[unit_id].read_mailbox_id, buffer, MAXLINE);
    if (received_size > buffer_size) {
        received_size = buffer_size;
    }

    args->arg4 = (void *) (long) (0);
    args->arg2 = (void *) (long) (received_size);
}

/**
 * This is the handler for terminal write system call
 * @param args
 */
void system_termwrite_handler(USLOSS_Sysargs *args) {
    char *buffer = (char *) args->arg1;
    int buffer_size = (int) (long) args->arg2;
    int unit_id = (int) (long) args->arg3;

    // remember buffer and buffer size
    MyPCB *process = get_process();
    strcpy(process->buffer_write, buffer);
    process->buffer_size_write = buffer_size;
    add_to_process_queue(&terminal_controls[unit_id].writing_queue, process);
    // wait until the daemon ensures the line is written
    blockMe();

    args->arg4 = (void *) (long) (0);
    args->arg2 = (void *) (long) (buffer_size);
}

/**
 * This is the handler for disk read system call
 * @param args
 */
void system_diskread_handler(USLOSS_Sysargs *args) {
    char *buffer = (char *) args->arg1;
    int sectors = (int) (long) args->arg2;
    int track_start = (int) (long) args->arg3;
    int sector_start = (int) (long) args->arg4;
    int unit = (int) (long) args->arg5;

    // verify that input is valid
    if (unit < 0 || unit >= DISK_UNITS || track_start < 0 || track_start >= BLOCKS_IN_DISK) {
        args->arg4 = (void *) (long) (-1);
        args->arg1 = (void *) (long) (-1);
        return;
    }

    // form a disk request
    MyPCB *process = get_process();
    process->disk_request.track = track_start;
    process->disk_request.type = READ;
    process->disk_request.blocks = sectors;
    process->disk_request.first_block = sector_start;
    add_to_process_queue(&disk_controls[unit].write_read_queue, process);

    // increment semaphore to signal disk daemon to wake up
    kernSemV(disk_controls[unit].sem_id);
    // wait until the request is processed
    blockMe();


    memcpy(buffer, process->disk_buffer, 512 * sectors);
    args->arg4 = (void *) (long) (0);
    args->arg1 = (void *) (long) (process->diskResponse.status);

}

/**
 * This is the handler for disk write system call
 * @param args
 */
void system_diskwrite_handler(USLOSS_Sysargs *args) {
    char *buffer = (char *) args->arg1;
    int sectors = (int) (long) args->arg2;
    int track_start = (int) (long) args->arg3;
    int sector_start = (int) (long) args->arg4;
    int unit = (int) (long) args->arg5;

    // verify that input is valid
    if (unit < 0 || unit >= DISK_UNITS || sector_start < 0 || sector_start >= BLOCKS_IN_DISK) {
        args->arg4 = (void *) (long) (-1);
        args->arg1 = (void *) (long) (-1);
        return;
    }

    // form a disk request
    MyPCB *process = get_process();
    process->disk_request.track = track_start;
    process->disk_request.type = WRITE;
    process->disk_request.blocks = sectors;
    process->disk_request.first_block = sector_start;
    memcpy(process->disk_buffer, buffer, 512 * sectors);
    add_to_process_queue(&disk_controls[unit].write_read_queue, process);

    // increment semaphore to signal disk daemon to wake up
    kernSemV(disk_controls[unit].sem_id);
    // block until the request is processed
    blockMe();

    args->arg4 = (void *) (long) (0);
    args->arg1 = (void *) (long) (process->diskResponse.status);
}

/**
 * The function gets the number of tracks in a given disk unit
 * @param disk_unit unit of disk: can be 0 or 1
 * @return number of tracks or -1 if error
 */
int get_number_of_tracks(int disk_unit) {
    USLOSS_DeviceRequest request;
    int number_of_tracks;
    request.opr = USLOSS_DISK_TRACKS;
    request.reg1 = &number_of_tracks;

    // Send the request to the disk unit
    int result = USLOSS_DeviceOutput(USLOSS_DISK_DEV, disk_unit, &request);
    if (result != USLOSS_DEV_OK) {
        // Handle the error
        return -1; // Indicate failure
    }

    // wait for the completion of the request
    int status;
    waitDevice(USLOSS_DISK_DEV, disk_unit, &status);


    if (status == USLOSS_DEV_READY) {
        return number_of_tracks; // Retrieve the number of tracks
    } else {
        return -1;
    }
}

/**
 * This is the handler for the disk size system call.
 * Since the information is static, only the first call
 * initiates the request to the disk.
 * @param args
 */
void system_disksize_handler(USLOSS_Sysargs *args) {
    int unit_id = (int) (long) args->arg1;

    gain_lock(&disk_controls[unit_id].tracks_lock);

    // check if disk size is yet know
    if (disk_controls[unit_id].disk_size.initialized == 0) {
        // if not, make TRACKS request to find out
        int tracks = get_number_of_tracks(unit_id);
        if (tracks < 0) {
            args->arg4 = (void *) (long) (-1);
            release_lock(&disk_controls[unit_id].tracks_lock);
            return;
        } else {
            // store this info for later requests.
            disk_controls[unit_id].disk_size.tracks = tracks;
            disk_controls[unit_id].disk_size.initialized = 1;
        }
    }

    args->arg1 = (void *) (long) (BYTES_IN_BLOCK);
    args->arg2 = (void *) (long) (BLOCKS_IN_DISK);
    args->arg3 = (void *) (long) (disk_controls[unit_id].disk_size.tracks);
    args->arg4 = (void *) (long) (0);

    release_lock(&disk_controls[unit_id].tracks_lock);
}

/*********** Terminal Daemon and its helper function **************/

/**
 * This function enables terminal interrupts by setting appropriate bits
 * @param unit terminal unit
 */
void enable_terminal_interrupts(int unit) {
    int ctrl = 0;
    ctrl = USLOSS_TERM_CTRL_RECV_INT(ctrl);
    ctrl = USLOSS_TERM_CTRL_XMIT_INT(ctrl);

    // Write the control value to the terminal device
    int response = USLOSS_DeviceOutput(USLOSS_TERM_DEV, unit, (void *) ((long) ctrl));
    if (response < 0) {
        print_error("Something went wrong with DeviceOutput", response);
    }
}

/**
 * Checks if the terminal is ready to read from
 * @param terminal_id
 * @param status
 * @return
 */
int is_terminal_ready_to_read(int terminal_id, int status) {
    return USLOSS_TERM_STAT_RECV(status) == USLOSS_DEV_BUSY;
}

/**
 * Checks if the terminal is ready to write to
 * @param terminal_id
 * @param status
 * @return
 */
int is_terminal_ready_to_write(int terminal_id, int status) {
    return USLOSS_TERM_STAT_XMIT(status) == USLOSS_DEV_READY;
}

/**
 * This is a part of the daemon that handles terminal reads
 * @param unit
 * @param status
 */
void handle_read(int unit, int status) {
    char ch = USLOSS_TERM_STAT_CHAR(status);

    if (ch == '\n' || terminal_controls[unit].read_buffer_count == MAXLINE) {
        terminal_controls[unit].read_buffer[terminal_controls[unit].read_buffer_count] = ch == '\n' ? '\n' : '\0';
        MboxCondSend(terminal_controls[unit].read_mailbox_id, terminal_controls[unit].read_buffer,
                     terminal_controls[unit].read_buffer_count + 1);
        terminal_controls[unit].read_buffer_count = 0;
    } else {
        terminal_controls[unit].read_buffer[terminal_controls[unit].read_buffer_count] = ch;
        terminal_controls[unit].read_buffer_count += 1;
    }
}

/**
 * Prepares control word for terminal output.
 *
 * @param ch Character to be output
 * @return Prepared control word with character and send bit set
 */
static unsigned short prepare_control_word(char ch) {
    unsigned short control = (ch << 8);  // Place character in character field
    control |= 0x1;  // Set send char bit
    return control;
}

/**
 * Sends output to terminal device.
 *
 * @param unit Terminal unit number
 * @param control Control word for output
 * @return Result of device output operation
 */
static int send_terminal_output(int unit, unsigned short control) {
    return USLOSS_DeviceOutput(USLOSS_TERM_DEV, unit, (void *) ((long) control));
}

/**
 * Handles write operations for a specific terminal unit.
 * Manages character output and process writing queue.
 *
 * @param unit Terminal unit number
 * @param status Status of the terminal (unused in this implementation)
 */
void handle_write(int unit, int status) {
    // Acquire terminal-specific write lock for thread-safe access
    gain_lock(&terminal_controls[unit].write_lock);

    MyPCB *writer = NULL;
    unsigned short control = 0;

    // Check if a process is currently writing
    if (terminal_controls[unit].writing_proc != NULL) {
        writer = terminal_controls[unit].writing_proc;

        // Prepare character for output
        char current_char = writer->buffer_write[writer->write_count];
        control = prepare_control_word(current_char);

        // Attempt device output
        int output_result = send_terminal_output(unit, control);
        if (output_result < 0) {
            print_error("Terminal output failed", output_result);
        }

        // Update writer progress
        if (++writer->write_count >= writer->buffer_size_write) {
            // Writing complete, reset and unblock process
            terminal_controls[unit].writing_proc = NULL;
            writer->write_count = 0;
            unblockProc(writer->id);
        }
    } else {
        // No current writer, attempt to get next process from queue

        writer = remove_from_process_queue(&terminal_controls[unit].writing_queue);

        // Exit if no processes waiting
        if (writer == NULL) {
            release_lock(&terminal_controls[unit].write_lock);
            return;
        }

        // Set up new writing process
        terminal_controls[unit].writing_proc = writer;

        // Prepare first character for output
        char first_char = writer->buffer_write[writer->write_count];
        control = prepare_control_word(first_char);

        // Send to device
        int output_result = send_terminal_output(unit, control);
        if (output_result < 0) {
            print_error("Terminal output failed", output_result);
        }

        // Increment write progress
        writer->write_count++;
    }

    // Release terminal write lock
    release_lock(&terminal_controls[unit].write_lock);
}

/**
 * This is the daemon for the terminal. It coordinates terminal systems calls.
 * Each terminal unit gets its own instance.
 * @param unit
 */
static void run_terminal_daemon(int unit) {
    int status = 0;

    while (1) {

        enable_terminal_interrupts(unit);
        waitDevice(USLOSS_TERM_DEV, unit, &status);

        if (is_terminal_ready_to_read(unit, status)) {
            handle_read(unit, status);
        }

        if (is_terminal_ready_to_write(unit, status)) {
            handle_write(unit, status);
        }
    }
}

/*********** Disk Daemon and its helper function **************/

/**
 * This function handles disk read requests atomically.
 * @param process abstraction of the process that made the request
 * @param unit disk unit
 * @return
 */
static int handle_disk_read(MyPCB *process, int unit) {
    DiskRequest read_request = process->disk_request;

    // Seek to the correct track
    USLOSS_DeviceRequest seekRequest = {.opr = USLOSS_DISK_SEEK, .reg1 =  (void *) ((long) read_request.track)};
    int status;
    if (USLOSS_DeviceOutput(USLOSS_DISK_DEV, unit, &seekRequest) != USLOSS_DEV_OK) {
        return -1; // Failed to send SEEK request
    }

    // Wait for SEEK to complete
    waitDevice(USLOSS_DISK_DEV, unit, &status);
    if (status == USLOSS_DEV_BUSY) {
        return -1;
    }

    // track does not exist
    if (read_request.track >= disk_controls[unit].disk_size.tracks) {
        return -1;
    }

    // Perform the READ operations
    for (int i = 0; i < read_request.blocks; i++) {
        USLOSS_DeviceRequest singleRequest;
        singleRequest.opr = USLOSS_DISK_READ;
        singleRequest.reg1 = (void *) ((long)((read_request.first_block + (i)) % 16));

        // address changes depending on which sector we are visiting.
        singleRequest.reg2 = &(process->disk_buffer[i * 512]);

        if (USLOSS_DeviceOutput(USLOSS_DISK_DEV, unit, &singleRequest) != USLOSS_DEV_OK) {
            return -1; // Failed to send WRITE request
        }

        waitDevice(USLOSS_DISK_DEV, unit, &status);
        if (status == USLOSS_DEV_BUSY) {
            return -1;
        }
    }

    return 0;
}

/**
 * This function handles disk write requests atomically.
 * @param process abstraction of the process that made the request
 * @param unit disk unit
 * @return
 */
static int handle_disk_write(MyPCB *process, int unit) {
    DiskRequest write_request = process->disk_request;

    // Seek to the correct track
    USLOSS_DeviceRequest seekRequest = {.opr = USLOSS_DISK_SEEK, .reg1 =  (void *) ((long) write_request.track)};
    int status;
    if (USLOSS_DeviceOutput(USLOSS_DISK_DEV, unit, &seekRequest) != USLOSS_DEV_OK) {
        return -1; // Failed to send SEEK request
    }

    // Wait for SEEK to complete
    // wait for the completion of the request
    waitDevice(USLOSS_DISK_DEV, unit, &status);
    if (status == USLOSS_DEV_BUSY) {
        return -1;
    }

    // track does not exist
    if (write_request.track >= disk_controls[unit].disk_size.tracks) {
        return -1;
    }

    // Perform the WRITE operations
    for (int i = 0; i < write_request.blocks; i++) {
        USLOSS_DeviceRequest singleRequest;
        singleRequest.opr = USLOSS_DISK_WRITE;
        singleRequest.reg1 = (void *) ((long)((write_request.first_block + (i)) % 16));

        // address changes depending on which sector we are visiting.
        singleRequest.reg2 = &(process->disk_buffer[i * 512]);
        if (USLOSS_DeviceOutput(USLOSS_DISK_DEV, unit, &singleRequest) != USLOSS_DEV_OK) {
            return -1; // Failed to send WRITE request
        }

        // Wait for WRITE to complete
        waitDevice(USLOSS_DISK_DEV, unit, &status);
        if (status == USLOSS_DEV_BUSY) {
            return -1;
        }
    }

    return 0;
}

/**
 * This function channels the disk request to the right function.
 * @param process abstraction of the process that made the request
 * @param unit disk unit
 * @return 0 if success. -1 if error
 */
static int handle_disk_request(MyPCB *process, int unit) {
    gain_lock(&disk_controls[unit].read_write_lock);

    int result = 0;

    if (process->disk_request.type == READ) {
        result = handle_disk_read(process, unit);
    } else {
        result = handle_disk_write(process, unit);
    }

    release_lock(&disk_controls[unit].read_write_lock);
    return result;
}

/**
 * This is the disk daemon. It coordinates disk system call requests.
 */
static void run_disk_daemon(int unit) {
    while (1) {
        // wait for the signal
        kernSemP(disk_controls[unit].sem_id);

        // set disk size properties if not yet initiated.
        if (disk_controls[unit].disk_size.initialized == 0) {
            int tracks = get_number_of_tracks(unit);
            disk_controls[unit].disk_size.tracks = tracks;
            disk_controls[unit].disk_size.initialized = 1;

        }

        // get process using c-scan/one-direction elevator algorithm
        MyPCB *process = remove_from_process_queue_elevator(&disk_controls[unit].write_read_queue,
                                                            disk_controls[unit].last_track);
        if (process != NULL) {
            int result = handle_disk_request(process, unit);
            process->diskResponse.status = result == -1 ? USLOSS_DEV_ERROR : result;
            disk_controls[unit].last_track = process->disk_request.track + process->disk_request.blocks - 1;
            unblockProc(process->id);
        }
    }
}

/*********** Clock Daemon and its helper function **************/

/**
 * The function checks if it is time for the process to wake up
 * @param proc
 * @return
 */
static int time_wake_up(MyPCB *proc) {
    int time_to_wake_up = proc->sleep_start + proc->sleep_duration;
    if (currentTime() >= time_to_wake_up) {
        return 1;
    } else return 0;
}

/**
 * This is the clock daemon. It coordinates clock system call requests.
 */
static void run_clock_daemon() {
    int status = 0;

    while (1) {
        waitDevice(USLOSS_CLOCK_DEV, 0, &status);

        if (is_process_queue_empty(&queue_manager.clock_queue)) continue;
        MyPCB *cur = queue_manager.clock_queue.next;

        // wake up each process which is ready to wake up
        while (cur) {
            if (time_wake_up(cur)) {
                remove_specific_proc(&queue_manager.clock_queue, cur);
                unblockProc(cur->id);
            }

            cur = cur->next;
        }
    }
}

/***** Bootstrap related functions **********/

/**
 * wrapper for the terminal daemon start function
 * @param args
 * @return
 */
static int wrapper_terminal(void *args) {
    run_terminal_daemon((int) (long) args);
    quit(1);
}

/**
 * wrapper for the terminal daemon start function
 * @param args
 * @return
 */
static int wrapper_disk(void *args) {
    run_disk_daemon((int) (long) args);
    quit(1);
}

/**
 * wrapper for the terminal daemon start function
 * @param args
 * @return
 */
static int wrapper_clock(void *args) {
    run_clock_daemon();
    quit(1);
}

/**
 * Launches service processes for phase 4
 */
void phase4_start_service_processes(void) {
    spork("Clock Daemon", wrapper_clock, NULL, USLOSS_MIN_STACK, MAX_PROC_PRIORITY);

    // start 4 terminal daemons
    for (int i = 0; i < TERMINAL_UNITS; i++) {
        spork("Terminal Daemon", wrapper_terminal, (void *) (long) i, USLOSS_MIN_STACK, MAX_PROC_PRIORITY);
    }

    // start 2 disk daemons
    for (int i = 0; i < DISK_UNITS; i++) {
        spork("Disk Daemon", wrapper_disk, (void *) (long) i, USLOSS_MIN_STACK, 5);
    }

}

/**
 * The function sets up terminal metadata
 */
void set_up_terminal_controls() {
    for (int i = 0; i < TERMINAL_UNITS; i++) {
        int write_lock_id = MboxCreate(1, 0);
        int writer_mailbox = MboxCreate(10, MAXLINE);
        terminal_controls[i].write_lock.mailbox_id = write_lock_id;
        terminal_controls[i].read_mailbox_id = writer_mailbox;
    }
}

/**
 * The function sets up disk metadata
 */
void set_up_disk_controls() {

    for (int i = 0; i < DISK_UNITS; i++) {
        int track_lock = MboxCreate(1, 0);
        int read_write_lock = MboxCreate(1, 0);
        disk_controls[i].tracks_lock.mailbox_id = track_lock;
        disk_controls[i].read_write_lock.mailbox_id = read_write_lock;
        kernSemCreate(0, &disk_controls[i].sem_id);
        disk_controls[i].last_track = -1;
    }
}

/**
 * This function is called by the testcase during bootstrap,
 * before any processes are running
 */
void phase4_init(void) {
    systemCallVec[SYS_SLEEP] = system_sleep_handler;
    systemCallVec[SYS_TERMREAD] = system_termread_handler;
    systemCallVec[SYS_TERMWRITE] = system_termwrite_handler;
    systemCallVec[SYS_DISKSIZE] = system_disksize_handler;
    systemCallVec[SYS_DISKREAD] = system_diskread_handler;
    systemCallVec[SYS_DISKWRITE] = system_diskwrite_handler;
    int global_id = MboxCreate(1, 0);
    if (global_id < 0) print_error("Error: could not create a mailbox.", -1);
    global_lock.mailbox_id = global_id;
    set_up_terminal_controls();
    set_up_disk_controls();
}