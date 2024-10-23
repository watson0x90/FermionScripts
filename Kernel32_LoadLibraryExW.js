// Helper function to send load library details
function logLibraryLoad(funcName, libPath) {
    var timestamp = new Date().toISOString();
    send(`[+] ${funcName} called at ${timestamp}`);
    send(`    |-> Library: ${libPath}`);
}

// Hook LoadLibraryExW
var pLoadLibraryExW = Module.findExportByName('Kernel32.dll', 'LoadLibraryExW');
if (pLoadLibraryExW) {
    Interceptor.attach(pLoadLibraryExW, {
        onEnter: function (args) {
            var sPath = args[0].readUtf16String();
            if (sPath) {
                logLibraryLoad('LoadLibraryExW', sPath);
            }
        }
    });
}

// Hook GetProcAddress to monitor function resolution from loaded DLLs
var pGetProcAddress = Module.findExportByName('Kernel32.dll', 'GetProcAddress');
if (pGetProcAddress) {
    Interceptor.attach(pGetProcAddress, {
        onEnter: function (args) {
            var hModule = args[0]; // Handle to the DLL module
            var pFunctionName = args[1]; // Function name or ordinal

            var functionName = pFunctionName.readUtf8String();
            if (functionName) {
                send(`[+] GetProcAddress called for function: ${functionName}`);
            } else {
                send(`[+] GetProcAddress called with ordinal: ${pFunctionName.toInt32()}`);
            }
        }
    });
}
