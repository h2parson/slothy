                               // Instructions:    1
                               // Expected cycles: 1
                               // Expected IPC:    1.00
                               //
                               // Cycle bound:     1.0
                               // IPC bound:       1.00
                               //
                               // Wall time:     0.03s
                               // User time:     0.03s
                               //
                               // ----- cycle (expected) ------>
                               // 0                        25
                               // |------------------------|----
        mul w10, w1, w2        // *.............................

                               // ------ cycle (expected) ------>
                               // 0                        25
                               // |------------------------|-----
        // mul w0, w1, w2      // *..............................
