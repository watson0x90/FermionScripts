// Hooking LoadLibraryExW for monitoring DLL loads and printing the call stack

// Helper function to send load library details
function logLibraryLoad(funcName, libPath, backtrace) {
    var timestamp = new Date().toISOString();
    send(`[+] ${funcName} called at ${timestamp}`);
    send(`    |-> Library: ${libPath}`);
    send(`    |-> Call stack:`);
    backtrace.forEach(function (addr) {
        send(`        ${addr}`);
    });
}

// Hook LoadLibraryExW
var pLoadLibraryExW = Module.findExportByName('Kernel32.dll', 'LoadLibraryExW');
if (pLoadLibraryExW) {
    Interceptor.attach(pLoadLibraryExW, {
        onEnter: function (args) {
            var sPath = args[0].readUtf16String();
            if (sPath) {
                var backtrace = Thread.backtrace(this.context, Backtracer.ACCURATE)
                    .map(DebugSymbol.fromAddress);
                logLibraryLoad('LoadLibraryExW', sPath, backtrace);
            }
        }
    });
}
