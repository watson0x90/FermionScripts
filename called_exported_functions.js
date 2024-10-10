// Check for exported functions called by an EXE.

let dllName = "example.dll";

let dllModule = Process.findModuleByName(dllName);

if (dllName) {
    send("[+] " + dllName + " is loaded at base address: " + dllModule.base);

    // Enumerate all exported functions from the DLL using the correct method on the module object
    let exports = dllModule.enumerateExports();

    send("[+] Hooking exported functions from "+dllName+":");
    
    // Hook each exported function
    exports.forEach(function (exp) {
        send("    |_ Hooking " + exp.name + " @ " + exp.address);

        // Attach an interceptor to each exported function
        Interceptor.attach(exp.address, {
            onEnter: function (args) {
                send("[+] Called function: " + exp.name);
            }
        });
    });
} else {
    send("[-] "+dllName+" is not loaded.");
}
