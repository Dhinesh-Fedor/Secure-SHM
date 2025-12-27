#include "sshm_utils.h"
#include <stdio.h>
#include <stdlib.h>

/* forward from sshm_daemon.c */
int sshm_daemon_run(void);

int main(int argc, char **argv){
    (void)argc; (void)argv;
    sshm_debug("[daemon]", "starting sshmd");
    return sshm_daemon_run();
}