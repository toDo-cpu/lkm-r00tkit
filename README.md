# Linux Kernel Module R00tki

This is a simple **lkm rootkit**. It work by hooking the syscall table.

With this rootkit you can prevent the attach of new **lkm** with `insmod`. It can hide from the userland. It also hide the binary file from the user.

To code this, I used this [blog](https://xcellerator.github.io/posts/linux_rootkits_01/) which is awefull to start the development of r00tkits.
