/*
 * Two process semaphore test.
 */

#include <usloss.h>
#include <usyscall.h>
#include <phase1.h>
#include "../phase2.h"
#include <phase3_usermode.h>
#include <stdio.h>

int Child1(void *);
int Child2(void *);

int semaphore;


int start3(void *arg)
{
    int pid, status;
    int sem_result;

    USLOSS_Console("start3(): started.  Creating semaphore.\n");

    sem_result = SemCreate(0, &semaphore);
    if (sem_result != 0) {
        USLOSS_Console("start3(): got non-zero semaphore result. Terminating...\n");
        Terminate(1);
    }

    USLOSS_Console("start3(): calling Spawn for Child1\n");
    Spawn("Child1", Child1, NULL, USLOSS_MIN_STACK, 2, &pid);
    USLOSS_Console("start3(): after spawn of %d\n", pid);

    USLOSS_Console("start3(): calling Spawn for Child2\n");
    Spawn("Child2", Child2, NULL, USLOSS_MIN_STACK, 2, &pid);
    USLOSS_Console("start3(): after spawn of %d\n", pid);

    Wait(&pid, &status);
    Wait(&pid, &status);

    USLOSS_Console("start3(): Parent done. Calling Terminate.\n");
    Terminate(0);
}


int Child1(void *arg) 
{
    USLOSS_Console("Child1(): starting, P'ing semaphore\n");
    SemP(semaphore);
    USLOSS_Console("Child1(): done\n");

    return 9;
}


int Child2(void *arg) 
{
    USLOSS_Console("Child2(): starting, V'ing semaphore\n");
    SemV(semaphore);
    USLOSS_Console("Child2(): done\n");

    return 9;
}

