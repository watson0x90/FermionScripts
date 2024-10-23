// Check for exported functions called by an EXE.

let dllName = "KernelBase.dll";

let dllModule = Process.findModuleByName(dllName);

if (dllModule) {
    send("[+] " + dllName + " is loaded at base address: " + dllModule.base);

    // Enumerate all exported functions from the DLL
    let exports = dllModule.enumerateExports();

    send("[+] Hooking exported functions from " + dllName + ":");
    
    // Hook each exported function
    exports.forEach(function (exp) {
        try {
            send("    |_ Hooking " + exp.name + " @ " + exp.address);

            // Attach an interceptor to each exported function
            Interceptor.attach(exp.address, {
                onEnter: function (args) {
                    send("[+] Called function: " + exp.name);
                }
            });
        } catch (err) {
            // If an error occurs, log it and continue with the next function
            send("[-] Failed to hook " + exp.name + ": " + err.message);
        }
    });
} else {
    send("[-] " + dllName + " is not loaded.");
}
