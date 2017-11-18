Recently we were provided a malware sample that contained some interesting strings that indicated it was packed with script2exe. Script2exe is a utility that can take a VBScript file and pack it into an executable. It is not in and of itself malicious, but can be used to package scripts that can do bad things. For this reason, many antivirus engines detect script2exe files as malicious regardless of their actual function. Use caution when investigating AV or EDR alerts on script2exe based malware.
 
Script2exe functions by packaging the original VBScript as an encrypted resource within a PE stub. The original script is retained in the EXE stub's resources section as a Bitmap resource numbered "129" after it is encrypted with RC4. Upon execution of the PE Stub, the resource is loaded into memory, decrypted, and executed.Script2exe Dumper

This is an IDA Python script that will run a script2exe packed script in a debugger and will dump out the RC4 encryption key and the plaintext version of the VBScript for analysis.

Tested on IDA 6.95.
