// Scan memory for a specific pattern
function scanMemory(stringToSearch, protection = 'r--') {

    // convert the string to a hex pattern
    let pattern = stringToHexWithSpaces(stringToSearch);

    // print what we are searching for
    send(`[BEGIN] Scanning memory for {string: ${stringToSearch}, hex: ${pattern}}`);
    
    let ranges = Process.enumerateRanges({ protection: protection, coalesce: false });
    let totalRanges = ranges.length;
    let foundCount = 0;
    
    send(`[INFO] Located ${totalRanges} memory ranges matching protection: ${protection}`);

    ranges.forEach(function (range) {
        Memory.scan(range.base, range.size, pattern, {
            onMatch: function (address, size) {
                send(`[+] Pattern found at: ${address.toString()}`);
                try {
                    // Read data before the found pattern
                    let preStringSize = 4096; // Number of bytes to read before the pattern
                    let preString = getASCIIString(address.sub(preStringSize), preStringSize);
                    send(`[PRECEDING ASCII] ${preString}`);

                    // Read the matched pattern + length
                    let asciiString = getASCIIString(address, 4096);
                    send(`[MATCH ASCII] ${asciiString}`);
                    
                } catch (error) {
                    send(`[!] Runtime error: ${error.message}`);
                }
                foundCount++;
            },
            onError: function (reason) {
                send(`[!] Error scanning memory range: ${reason}`);
            },
            onComplete: function () {
                // No action needed here
            }
        });
    });

    send(`[FINISH] Scanning complete. Found pattern ${foundCount} times.`);
}
// Convert the string to hex
function stringToHexWithSpaces(str) {
  let hex = "";

  for (let i = 0; i < str.length; i++) {
    // Convert character to hex and pad with a 0 if needed
    const hexChar = str.charCodeAt(i).toString(16).padStart(2, "0");
    hex += hexChar + " "; 
  }

  // Remove trailing space
  return hex.trim(); 
}

// Get only the ASCII so we dont have to deal with the hex dump
function getASCIIString(buffPtr, buffSize) {
    let asciiString = "";

    for (let i = 0; i < buffSize; i++) {
        try {
            let byte = buffPtr.add(i).readU8();
            if (byte >= 32 && byte <= 126) { // Check if the byte is a printable ASCII character
                asciiString += String.fromCharCode(byte);
            }
        } catch (error) {
            send(`[!] Error reading memory at offset ${i}: ${error.message}`);
            break;
        }
    }

    return asciiString;
}

// Continuous scan with sleep of every 1 sec
function startContinuousScan(pattern, protection = 'r--') {
    setInterval(function () {
        try {
            scanMemory(pattern, protection);
        } catch (error) {
            send(`[!] Error during scanning: ${error.message}`);
        }
    }, 1000); // Scan every 1 second
}

// Scan for specified string
startContinuousScan("secretTunnel");
