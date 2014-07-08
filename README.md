SHIPS
=====

SHIPS - Shell Intrusion Prevention Script

SHIPS is a simple Shell-Script, which sniffes your log-files for multiple regex'es
and executes a command to prevent an attack. 

The primary goal of SHIPS is, to provide a tool like "fail2ban" for
embedded platforms like OpenWRT so it will be optimised for busybox's ash.



Known Problems
=====
* logread doesn't quit after stopping SHIPS. No fix atm.
