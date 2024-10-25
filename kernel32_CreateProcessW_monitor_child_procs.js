const kernel32 = Module.findExportByName("kernel32.dll", "CreateProcessW");

if (kernel32) {
    Interceptor.attach(kernel32, {
        onEnter: function (args) {
            const lpApplicationName = args[0];
            const lpCommandLine = args[1];

            if (lpApplicationName) {
                send("[*] Creating process: " + lpApplicationName.readUtf16String());
            } else if (lpCommandLine) {
                send("[*] Creating process with command line: " + lpCommandLine.readUtf16String());
            }

            // Extract the process handle (which is the child process ID)
            this.processId = args[5].toInt32();
        },
        onLeave: function (retval) {
            if (retval.toInt32() !== 0) {
                send("[+] Child process created with PID: " + this.processId);

                // Attach to the child process by PID
                const childPid = this.processId;

                // Attach to the child process and hook into its functions
                attachAndMonitor(childPid);
            } else {
                send("[-] Failed to create child process");
            }
        }
    });
}

function attachAndMonitor(pid) {
    send("[*] Attaching to child process PID: " + pid);
    
    // Spawn and attach to the child process
    const session = Process.getModuleByName("ntdll.dll"); // Example: Monitoring ntdll.dll

    session.enumerateExports().forEach(function (exp) {
        send("Hooking: " + exp.name);
        try {
            Interceptor.attach(exp.address, {
                onEnter: function (args) {
                    send("[*] " + exp.name + " called");
                }
            });
        } catch (e) {
            send("[-] Error hooking: " + exp.name);
        }
    });
}
