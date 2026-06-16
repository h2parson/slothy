                               // Instructions:    1
                               // Expected cycles: 1
                               // Expected IPC:    1.00
                               //
                               // Cycle bound:     1.0
                               // IPC bound:       1.00
                               //
                               // Wall time:     0.07s
                               // User time:     0.07s
                               //
                               // ----- cycle (expected) ------>
                               // 0                        25
                               // |------------------------|----
        add x11, x1, x2        // *.............................

                               // ------ cycle (expected) ------>
                               // 0                        25
                               // |------------------------|-----
        // add x0, x1, x2      // *..............................
