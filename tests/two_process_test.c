/**
 * two_process_test.c
 *
 * This program tests the multi-process workflow of the SSHM library.
 * 1. It creates a segment.
 * 2. It forks into a Parent (Writer) and Child (Reader).
 * 3. The Parent writes a secret message.
 * 4. The Child reads the message and verifies it.
 *
 * To compile (assuming libsshm.so is in /usr/local/lib):
 * gcc -o two_process_test two_process_test.c -I/path/to/include -L/path/to/lib -lsshm -lsodium -lpthread
 *
 * Or, if your library is in the build/lib folder:
 * gcc -o build/bin/two_process_test two_process_test.c -Iinclude -Lbuild/lib -lsshm -lsodium -lpthread
 *
 * To run (must be in same dir as sshmd):
 * sudo LD_LIBRARY_PATH=./build/lib ./build/bin/two_process_test
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/wait.h>
#include <errno.h>
#include "sshm.h" // The only header we need!

// ANSI Colors for logging
#define C_RESET "\033[0m"
#define C_GRN   "\033[1;32m" // Process A (Writer)
#define C_BLU   "\033[1;34m" // Process B (Reader)
#define C_CYN   "\033[1;36m" // System / Success
#define C_RED   "\033[1;31m" // Error

const char *SEGMENT_NAME = "ipc_test_segment";
const char *SECRET_MESSAGE = "Hello Process B! This is Process A.";
const size_t SEGMENT_SIZE = 4096;

/**
 * Process B: The Receiver
 * This code is run only by the child process.
 */
int run_receiver_process() {
    printf(C_BLU "[B] Receiver (PID: %d) started.\n" C_RESET, getpid());

    // Initialize the library for this process
    if (sshm_init() != 0) {
        fprintf(stderr, C_RED "[B] sshm_init() failed: %s\n" C_RESET, sshm_last_error());
        return 1;
    }

    char read_buffer[1024];
    ssize_t bytes_read = -1;
    int retries = 0;

    printf(C_BLU "[B] Polling for message from Process A...\n" C_RESET);

    // Poll the segment up to 5 times
    for (retries = 0; retries < 5; retries++) {
        // We call sshm_read, which does a full open-read-close
        bytes_read = sshm_read(SEGMENT_NAME, read_buffer, sizeof(read_buffer) - 1, 1); // 1 = decrypt

        if (bytes_read > 0) {
            // Success! Data was read.
            read_buffer[bytes_read] = '\0';
            break;
        }

        // If bytes_read == 0, the segment was empty. Wait and retry.
        if (bytes_read == 0) {
            printf(C_BLU "[B] Segment was empty. Retrying...\n" C_RESET);
        }

        // If bytes_read < 0, an error occurred
        if (bytes_read < 0) {
            fprintf(stderr, C_RED "[B] sshm_read() failed: %s\n" C_RESET, sshm_last_error());
            // This could be a "deny" from the daemon, or segment not found.
            // We'll retry in case it was a timing issue.
        }
        
        usleep(500 * 1000); // Wait 500ms
    }

    // Check final result
    if (bytes_read <= 0) {
        fprintf(stderr, C_RED "[B] FAILURE: Failed to read message from Process A.\n" C_RESET);
        return 1;
    }

    // We have data, now verify it
    if (strcmp(read_buffer, SECRET_MESSAGE) == 0) {
        printf(C_CYN "[B] SUCCESS! Verified secret message:\n" C_RESET);
        printf(C_BLU "    -> \"%s\"\n" C_RESET, read_buffer);
        return 0; // Success
    } else {
        fprintf(stderr, C_RED "[B] FAILURE: Data mismatch!\n" C_RESET);
        fprintf(stderr, C_RED "    Expected: \"%s\"\n" C_RESET, SECRET_MESSAGE);
        fprintf(stderr, C_RED "    Got:      \"%s\"\n" C_RESET, read_buffer);
        return 1; // Failure
    }
}

/**
 * Process A: The Sender
 * This code is run only by the parent process.
 */
int run_sender_process() {
    printf(C_GRN "[A] Sender (PID: %d) started.\n" C_RESET, getpid());
    
    // We already ran sshm_init() in main before forking.
    // We will also run create in main, so here we just write.

    // Give the receiver a moment to start polling
    sleep(1); 

    printf(C_GRN "[A] Writing secret message to segment...\n" C_RESET);
    ssize_t bytes_written = sshm_write(
        SEGMENT_NAME, 
        SECRET_MESSAGE, 
        strlen(SECRET_MESSAGE), 
        1 // 1 = encrypt
    );

    if (bytes_written < 0) {
        fprintf(stderr, C_RED "[A] sshm_write() failed: %s\n" C_RESET, sshm_last_error());
        return 1; // Failure
    }

    printf(C_GRN "[A] Wrote %zd bytes. Waiting for Process B to finish.\n" C_RESET, bytes_written);
    return 0; // Success
}

int main() {
    printf(C_CYN "[SYSTEM] Starting two-process test...\n" C_RESET);
    
    // Set debug mode for the library if you want
    // setenv("SSHM_DEBUG", "1", 1);

    // 1. Initialize library in the main process.
    // This checks if the daemon is alive.
    if (sshm_init() != 0) {
        fprintf(stderr, C_RED "[SYSTEM] sshm_init() failed. Is the daemon running?\n" C_RESET);
        fprintf(stderr, C_RED "    -> %s\n" C_RESET, sshm_last_error());
        return 1;
    }

    // 2. Create the segment.
    // We do this *before* forking to ensure it exists.
    printf(C_CYN "[SYSTEM] Creating segment '%s'...\n" C_RESET, SEGMENT_NAME);
    
    /* --- FIX: Use new API with SSHM_MODE_OVERWRITE --- */
    if (sshm_create(SEGMENT_NAME, SEGMENT_SIZE, 1, SSHM_MODE_OVERWRITE) != 0) {
        // This might fail if the segment is left over from a previous bad run.
        // Let's try to destroy it and re-create it once.
        fprintf(stderr, C_RED "[SYSTEM] Create failed (may exist). Destroying and retrying...\n" C_RESET);
        sshm_destroy(SEGMENT_NAME); // Best-effort cleanup
        
        /* --- FIX: Use new API with SSHM_MODE_OVERWRITE --- */
        if (sshm_create(SEGMENT_NAME, SEGMENT_SIZE, 1, SSHM_MODE_OVERWRITE) != 0) {
            fprintf(stderr, C_RED "[SYSTEM] Re-create failed: %s\n" C_RESET, sshm_last_error());
            return 1;
        }
    }
    printf(C_CYN "[SYSTEM] Segment created. Forking processes...\n" C_RESET);

    // 3. Fork into Process A (Parent) and Process B (Child)
    pid_t pid = fork();

    if (pid < 0) {
        // Fork failed
        fprintf(stderr, C_RED "[SYSTEM] fork() failed: %s\n" C_RESET, strerror(errno));
        sshm_destroy(SEGMENT_NAME);
        return 1;
    }

    if (pid == 0) {
        // --- This is Process B (Child / Receiver) ---
        int receiver_status = run_receiver_process();
        exit(receiver_status); // Exit child with success (0) or failure (1)

    } else {
        // --- This is Process A (Parent / Sender) ---
        int sender_status = run_sender_process();

        // Wait for the child process to exit
        int child_exit_status;
        wait(&child_exit_status);

        // 4. Cleanup
        printf(C_CYN "[SYSTEM] Process B exited. Cleaning up segment...\n" C_RESET);
        sshm_destroy(SEGMENT_NAME);
        printf(C_CYN "[SYSTEM] Test finished.\n" C_RESET);

        // Final result:
        // Test fails if EITHER the sender failed OR the child exited with an error.
        if (sender_status != 0 || WEXITSTATUS(child_exit_status) != 0) {
            fprintf(stderr, C_RED "\n*** TEST FAILED ***\n" C_RESET);
            return 1;
        } else {
            printf(C_CYN "\n*** TEST PASSED ***\n" C_RESET);
            return 0;
        }
    }
}