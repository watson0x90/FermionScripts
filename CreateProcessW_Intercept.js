var ptrCreateProcessW = Module.findExportByName("Kernel32.dll", "CreateProcessW");

// Global storage for the new command line buffer
var newCmdPtr = null;
let execCount = 0;

Interceptor.attach(ptrCreateProcessW, {
    onEnter: function (args) {
        var lpCommandLine = args[1].readUtf16String();
        send("\n[#] CreateProcessW");
        send("[#] Original command: " + lpCommandLine);

        // Correctly formatted new command line
        let new_lpCommandLine = "C:\\Windows\\System32\\cmd.exe /C C:\\Windows\\System32\\calc.exe";

        if (execCount != 1) {
            // Allocate buffer large enough for the string plus a null-terminator (UTF-16, 2 bytes per char)
            var bufferSize = (new_lpCommandLine.length + 1) * 2; // +1 for the null terminator, *2 for UTF-16
            newCmdPtr = Memory.alloc(bufferSize);
            
            // Write the new command line string into the allocated memory
            newCmdPtr.writeUtf16String(new_lpCommandLine);

            // Replace the old command line argument with the new one
            args[1] = newCmdPtr;

            send("[#] Modified Command Line: " + new_lpCommandLine);

            execCount += 1;

            // Confirm that the command line has been correctly set
            var conf_lpCommandLine = args[1].readUtf16String();
            send("[##] Confirming Command Line: " + conf_lpCommandLine);
        }
    },
    onLeave: function (retval) {
        send("Process created (CreateProcessW).");
    }
});

var ptrCreateProcessInternalW = Module.findExportByName("kernelbase.dll", "CreateProcessInternalW");

Interceptor.attach(ptrCreateProcessInternalW, {
    onEnter: function (args) {
        // `args[2]` corresponds to `lpCommandLine`
        var lpCommandLine = args[2].readUtf16String();
        send("\n[#] CreateProcessInternalW called.");
        send("[#] Original command: " + lpCommandLine);

    },
    onLeave: function (retval) {
        send("Process created (CreateProcessInternalW).");
    }
});

