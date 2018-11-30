/**
 *  Initialize a seccomp context
 *      seccomp_init() is the method used
 *      SCMP_ACT_ALLOW - flag indicates that by default we want to ALLOW all system calls
 **/


scmp_filter_ctx seccomp_ctx = seccomp_init(SCMP_ACT_ALLOW);     
if (!seccomp_ctx) {
    fprintf(stderr, "seccomp initialization failed: %m\n");
    return EXIT_FAILURE;
}


int filter_set_status = seccomp_rule_add(
                                            seccomp_ctx,            // the context to which the rule applies
                                            SCMP_FAIL,              // action to take on rule match
                                            SCMP_SYS(unshare),   // get the sys_call number using SCMP_SYS() macro
                                            1,                     // any additional argument matches
                                            SCP_A0(SCMP_CMP_MASKED_EQ, CLONE_NEWUSER, CLONE_NEWUSER)
                                        );