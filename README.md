# Securitylab Project - Root Privileges Reverse Shell

## Team Member
<b>Sittichok Thanomkulrat and Xianze Zhan

## Tested Environment
Ubuntu 16.04(64 bit) with Kernel 4.4.0

## What Does it do?
We implemented a rootkit module. It can hide itself from the module list and grant the root access for standard user after it has been installed. The non-root user can then run the reverse shell script to open a root reverse shell and connect back to the attacker. 

## File You May Care
- install_rootkit.sh
- reverse_shell.sh
- rootkit.c
- rootkit.h

## How to Run? <br />
On Attacker side: <br />
  nc -l -p <listen_port> -vvv <br />

On target bot side: <br />

   make <br />
  sudo ./install_rootkit.sh <br />
You may modify the attacker server ip address & listen port in the script <br />
