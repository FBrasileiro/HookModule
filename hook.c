#include <linux/module.h>
#include <linux/init.h>
#include <linux/kernel.h>
#include <linux/unistd.h>
#include <asm/unistd.h>
#include <linux/kallsyms.h>
#include <linux/syscalls.h>
#include <linux/uaccess.h>

MODULE_AUTHOR("Felipe Brasileiro");
MODULE_DESCRIPTION("Simple module that hooks read and write syscalls for 'cat' and 'ls'");
MODULE_LICENSE("GPL");
MODULE_VERSION("1.0");

extern unsigned long __force_order;
static inline void write_forced_cr0(unsigned long value)
{
    asm volatile("mov %0,%%cr0"
                 : "+r"(value), "+m"(__force_order));
}

unsigned long **syscall_table;
unsigned long cr0;

asmlinkage long (*original_read)(unsigned int, char __user *, size_t);
asmlinkage long (*original_write)(unsigned int, const char __user *, size_t);

asmlinkage long my_read(unsigned int fd, char __user *buffer, size_t count)
{
    long ret;
    ret = original_read(fd, buffer, count);
    if (fd > 2)
    {
        if (!strcmp(current->comm, "cat") || !strcmp(current->comm, "ls"))
        {
            printk(KERN_INFO "%s called read system call\n", current->comm);
        }
    }
    return ret;
}

asmlinkage long my_write(unsigned int fd, char __user *buffer, size_t count)
{
    long ret;
    ret = original_write(fd, buffer, count);
    if (fd > 2)
    {
        if (!strcmp(current->comm, "cat") || !strcmp(current->comm, "ls"))
        {
            printk(KERN_INFO "%s called write system call\n", current->comm);
        }
    }
    return ret;
}

static int __init m_init_(void)
{
    syscall_table = (unsigned long **)kallsyms_lookup_name("sys_call_table");
    if (!syscall_table)
        return -1;
    printk(KERN_INFO "[+] My Module: Initializing...\n");
    printk(KERN_INFO "[*] Address of Syscall table: %p", syscall_table);

    write_forced_cr0(read_cr0() & ~0x10000);

    original_read = (void *)syscall_table[__NR_read];
    syscall_table[__NR_read] = (unsigned long *)my_read;

    original_write = (void *)syscall_table[__NR_write];
    syscall_table[__NR_write] = (unsigned long *)my_write;

    write_forced_cr0(read_cr0() | 0x10000);
    return 0;
}

static void __exit m_exit_(void)
{
    write_forced_cr0(read_cr0() & ~0x10000);
    syscall_table[__NR_read] = (unsigned long *)original_read;
    syscall_table[__NR_write] = (unsigned long *)original_write;
    write_forced_cr0(read_cr0() | 0x10000);
    printk(KERN_INFO "[-] My Module: Unloading...\n");
}
module_init(m_init_);
module_exit(m_exit_);