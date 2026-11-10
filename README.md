Linux Kernel Cryptographic Device Driver

A custom Linux character device driver written in C that performs real-time Caesar and XOR encryption/decryption on data streams directly at the OS kernel level.

Features

Kernel-Level Encryption: Implements both Caesar cipher and XOR cryptographic algorithms operating within kernel space.

Memory Management: Utilizes dynamic kernel memory allocation (kmalloc/kfree) with strict boundary checks on file position offsets to prevent buffer overflows.

Safe Data Transfer: Securely bridges user space and kernel space utilizing copy_to_user and copy_from_user, ensuring state isolation across multiple file descriptors via private data structures.

IOCTL Interface: Exposes custom ioctl commands to User Space for dynamic state management, such as key modification and read-state toggling (raw vs. decrypted).

Files in this Repository

encdec.c / encdec.h: The kernel module source code and header defining the standard POSIX file operations and IOCTL commands.

test.c: A user space application to interface with the device nodes and validate the driver.

Makefile: Kbuild script to compile the kernel module.

load / unload: Bash scripts to insert (insmod) and remove (rmmod) the module, and automatically manage device nodes via mknod.

Build and Run Instructions

Compile the kernel module:

make


Load the module and create device nodes:

sudo ./load


Compile and run the User Space test program:

gcc test.c -o test
./test


Unload the module and clean up:

sudo ./unload
make clean