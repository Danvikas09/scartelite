#!/bin/sh
# Runs one demo per course outcome. Usage: ./demo.sh
set -e
S=./stracelite
hdr() { printf '\n\n########## %s ##########\n' "$1"; }
hdr "CO1/CO5  file syscalls + fd->path (inode-backed files)"
$S -e trace=file -- tests/t_files 2>&1 | tail -8
hdr "CO2      fork / exec / wait lifecycle"
$S -f -e trace=process -- tests/t_fork 2>&1 | grep -E "fork|exec|wait4|exit" | grep -v ENOENT
hdr "CO3      signals + pipe IPC"
$S -e trace=signal,write -- tests/t_signal 2>&1 | tail -6
$S -f -e trace=ipc -- tests/t_fork 2>&1 | grep pipe
hdr "CO4      memory: mmap, demand paging, page faults, COW"
$S -f -m -- tests/t_mem 2>&1 | grep -E "\[mem pid.*(fault|VmRSS)|memory syscalls|16777216"
hdr "CO6      threads + mutex -> futex, clone"
$S -f -c -- tests/t_threads 2>&1 | grep -E "clone|futex|counter"
hdr "Summary table (-c)"
$S -c -- ls / 2>&1 >/dev/null | tail -14
