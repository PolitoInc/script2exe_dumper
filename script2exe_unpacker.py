from idautils import *
from idaapi import *


def getInlineRandFuncAddress():
    return LocByName("_rand")


def getCallToRC4(start_ea):
    # Get Function end address
    func_end_ea = GetFunctionAttr(start_ea, FUNCATTR_END)
    head = NextHead(start_ea, func_end_ea)
    while head != BADADDR:
        if GetMnem(head) == "call":
            return head
        head = NextHead(head, func_end_ea)


# First, get the address of the _rand function
rand_addr = getInlineRandFuncAddress()

if rand_addr == BADADDR:
    print "[*] ERROR: _rand function not found in this binary. Are you sure it's script2exe?"
    exit(1)

print "Located _rand at 0x%08x" % (rand_addr)

# Get the address where _rand is called
rand_xref = RfirstB(rand_addr)

if rand_xref == BADADDR:
    print "[*] Error: No xrefs to _rand were identified."
    exit(1)

# Get the address of the call to the RC4 function
call_rc4_addr = getCallToRC4(rand_xref)
if call_rc4_addr == BADADDR:
    print "[*] Error: Unable to find CALL instruction after RC4 key initialization."

# Add a breakpoint at the call to the RC4 decryption
print "RC4 decryption function called at 0x%08x" % (call_rc4_addr)
AddBpt(call_rc4_addr)

# Ask the user if they want to execute the program and run to the breakpoint
response = AskYN(0, "Run program to call to RC4 decryption function?")
if response == 1:
    # Run to the breakpoint
    RunTo(call_rc4_addr)

    # Wait for the debugger to suspend the process
    event = GetDebuggerEvent(WFNE_SUSP, -1)

    # Read the EAX register which contains the length of the encrypted buffer in memory
    buffer_length = GetRegValue("eax")

    # Read the decryption key and display it
    key_addr = Dword(GetRegValue("esp") + 4)
    key = GetString(key_addr, 32, ASCSTR_C)
    print "Found RC4 decryption key %s" % (key)

    # Step over the decryption function
    StepOver()
    GetDebuggerEvent(WFNE_SUSP, -1)

    # Once we've stepped over the decryption function, the decrypted buffer is now in memory
    # EAX points to the decrypted buffer
    plaintext_addr = GetRegValue("eax")
    print "Plaintext buffer located at 0x%08x" % (plaintext_addr)
    Jump(plaintext_addr)

    # Ask if we want to dump the plaintext buffer
    response = AskYN(0, "Dump decrypted buffer to file?")
    if response == 1:
        filename = AskFile(1, "*.*", "Output file selection")
        with open(filename, "wb") as outfile:
            plaintext = GetManyBytes(plaintext_addr, buffer_length, 1)
            outfile.write(plaintext)