#!/usr/bin/sh

cd /sys/fs/cgroup/cpuset
mkdir test
cd test
echo "0" > cpuset.cpus
echo 0 > cpuset.mems
echo $$ > cgroup.procs
