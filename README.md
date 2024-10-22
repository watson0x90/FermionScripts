# Fermion Scripts
## Description
These are a collection of Fermion Scripts that I have found helpful while performing reverse engineering. 

## Script Names
- called_exported_functions.js - When you know a DLL is being loaded, you want to see what exported functions are being called.
- scan_memory.js - Scan the current attached process for interesting strings.
- CreateProcessW_Intercept.js - Intercept CreateProcessW and change the command line for process creation. I added a counter to ensure we are not launching the command multiple times, but this can be changed. 
  
## Helpful Links
- https://github.com/FuzzySecurity/Fermion
- https://github.com/frida/frida
- https://labs.calypso.pub/windows-instrumentation-with-frida
- https://github.com/lymbin/frida-scripts/blob/master/frida-memory-dumper.py
- https://github.com/FuzzySecurity/Fermion/blob/master/Examples
