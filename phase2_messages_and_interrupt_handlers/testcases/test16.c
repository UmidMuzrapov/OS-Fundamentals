
/* tests for exceeding the number of slots. start2 creates mailboxes whose
 * total slots will exceed the system limit. start2 then starts doing
 * conditional sends to each slot of each mailbox until it gets an error.
 */

#include <stdio.h>
#include <usloss.h>
#include <phase1.h>
#include <phase2.h>

int mboxids[50];



int start2(void *arg)
{
    int boxNum, slotNum, result;

    USLOSS_Console("start2(): started, trying to exceed systemwide mailslots...\n");

    /* 50 mailboxes, capacity 55 each.  Each is individually legal, but if they
     * all backlog at the same time, then that will consume the system capacity
     * of MAXSLOTS=2500 mail messages.
     */

    for (boxNum = 0; boxNum < 50; boxNum++)
    {
        mboxids[boxNum] = MboxCreate(55, 0);
        if (mboxids[boxNum] < 0)
            USLOSS_Console("start2(): MailBoxCreate returned id less than zero, id = %d\n", mboxids[boxNum]);
    }

    for (boxNum = 0; boxNum < 50; boxNum++)
    {
        for (slotNum = 0; slotNum < 55; slotNum++)
        {


            result = MboxSend(mboxids[boxNum], NULL,0);

            if (result == -2)
            {
                USLOSS_Console("No slots available: mailbox %d and slot %d\n", boxNum, slotNum);
                quit(0);
            }
            else if (result != 0)
            {
                USLOSS_Console("UNEXPECTED ERROR %d: mailbox %d and slot %d\n", result, boxNum, slotNum);
                quit(100);
            }
        }
    }

    USLOSS_Console("ERROR: You should not get here!!!\n");
    quit(100);
}

