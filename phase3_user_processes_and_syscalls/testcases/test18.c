/* recursive terminate test */

#include <usloss.h>
#include <usyscall.h>
#include <phase1.h>
#include "../phase2.h"
#include <phase3_usermode.h>
#include <stdio.h>

int Child1(void *);
int Child2(void *);
int Child3(void *);

int sem1;


int start3(void *arg)
{
    int pid;
    int status;

    USLOSS_Console("start3(): started\n");

    Spawn("Child1", Child1, "Child1", USLOSS_MIN_STACK, 4, &pid);
    USLOSS_Console("start3(): spawned process %d\n", pid);

    Wait(&pid, &status);
    USLOSS_Console("start3(): child %d returned status of %d\n", pid, status);

    USLOSS_Console("start3(): done\n");
    Terminate(0);
}


int Child1(void *arg) 
{
    int pid;
    int status;

    GetPID(&pid);
    USLOSS_Console("%s(): starting, pid = %d\n", arg, pid);

    Spawn("Child2", Child2, "Child2", USLOSS_MIN_STACK, 2, &pid);
    USLOSS_Console("%s(): spawned process %d\n", arg, pid);

    Wait(&pid, &status);
    USLOSS_Console("%s(): child %d returned status of %d\n", arg, pid, status);

    Spawn("Child3", Child3, "Child3", USLOSS_MIN_STACK, 5, &pid);
    USLOSS_Console("%s(): spawned process %d\n", arg, pid);

    Wait(&pid, &status);
    USLOSS_Console("%s(): child %d returned status of %d\n", arg, pid, status);

    USLOSS_Console("%s(): done\n", arg);
    Terminate(9);
}

int Child2(void *arg) 
{
    int pid;

    GetPID(&pid);
    USLOSS_Console("%s(): starting, pid = %d\n", arg, pid);

    Spawn("Child2a", Child3, "Child2a", USLOSS_MIN_STACK, 5, &pid);
    USLOSS_Console("%s(): spawned process %d\n", arg, pid);

    Spawn("Child2b", Child3, "Child2b", USLOSS_MIN_STACK, 5, &pid);
    USLOSS_Console("%s(): spawned process %d\n", arg, pid);

    Spawn("Child2c", Child3, "Child2c", USLOSS_MIN_STACK, 5, &pid);
    USLOSS_Console("%s(): spawned process %d\n", arg, pid);

    Terminate(10);
}


int Child3(void *arg) 
{
    USLOSS_Console("%s(): starting\n", arg);
    Terminate(11);
}

