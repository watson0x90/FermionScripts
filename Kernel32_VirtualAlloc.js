let pVirtualAlloc = Module.findExportByName("Kernel32.dll", "VirtualAlloc");

Interceptor.attach(pVirtualAlloc, {
    onEnter: function(args) {
        send("[>] Called VirtualAlloc");
        send("    |_ lpAddress:           " + args[0]);
        send("    |_ dwSize:              " + args[1]);
        send("    |_ flAllocationType:    " + args[2]);
        send("    |_ flProtect:           " + args[3]);
    },
    onLeave: function(retval) {
        send("[<] VirtualAlloc returned: " + retval);
    }
});
