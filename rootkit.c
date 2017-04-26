#define LINUX

#include <linux/module.h>
#include <linux/kernel.h>

#include <linux/proc_fs.h>
#include <linux/list.h>
#include <linux/uaccess.h>
#include <linux/spinlock_types.h>
#include <linux/slab.h>
#include <linux/jiffies.h>
#include <linux/timer.h>

#include "rootkit.h"


MODULE_LICENSE("GPL");
MODULE_AUTHOR("thanomk");
MODULE_DESCRIPTION("CS460-project");

#define PROCFS_NAME "CS460"
#define TIMEOUT_INTERVAL 5 //seconds

static struct proc_dir_entry *proc_dir;
static struct proc_dir_entry *proc_dir_entry;

// Create new lock
static spinlock_t lock;

// Create new process_info struct
struct processInfo{

  unsigned long time;
  unsigned long pid;
  struct list_head list;

};

// for /proc file 
struct file_operations procFile_fops = {

    .owner = THIS_MODULE,
    .read = mp1_read,
    .write = mp1_write,

};

// Create kernel list
LIST_HEAD(procList);

// Create new timer
static struct timer_list timer;

// Create new workqueue
static struct workqueue_struct *workqueue;
static struct work_struct *works;


static ssize_t mp1_read(struct file *file, char __user *buffer, size_t count, loff_t *data){

    int copied;
    unsigned long tmpFlags;
    char *buf;
    struct processInfo *currProc; // use as loop cursor
    struct processInfo *n; // temp storage for loop

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
        copied += snprintf(buf+copied, sizeof(buf), "%lu: %lu\n", currProc->pid,\
         cputime_to_jiffies(currProc->time));
    }

    spin_unlock_irqrestore(&lock, tmpFlags);

    if(copy_to_user(buffer, buf, copied)){
        return -EFAULT;
    }

    kfree(buf);

    buf = NULL;

    return copied;
}


static ssize_t mp1_write(struct file *file, const char __user *buffer, size_t count, loff_t *data){

    unsigned long tmpFlags;
    char *buf;


    struct processInfo *newProc;
    struct processInfo *currProc; // use as loop cursor
    struct processInfo *n; // temp storage for loop

    buf = (char *) kzalloc(count, GFP_KERNEL);

    if(copy_from_user(buf, buffer, count)){
      return -EFAULT;
    }

    newProc = (struct processInfo *)kzalloc(sizeof(struct processInfo), GFP_KERNEL);
    

    if(kstrtoul(buf, 10, &newProc->pid) < 0){
        pr_alert("Failed to convert user input.");

        kfree(buf);
        kfree(newProc);

        buf = NULL;
        newProc = NULL;

        return -EINVAL;
    }
    
    //Check if process existed
    // if(get_cpu_use(newProc->pid, &newProc->time) < 0){

    //     pr_warning("None existing process registration detected.");

    //     kfree(buf);
    //     kfree(newProc);

    //     buf = NULL;
    //     newProc = NULL;

    //     return -1;
    // }

    //Check for pid duplication
    list_for_each_entry_safe(currProc, n, &procList, list){

        if(currProc->pid == newProc->pid){
            
            pr_warning("Duplicated pid registration detected.");
            
            kfree(buf);
            kfree(newProc);

            buf = NULL;
            newProc = NULL;

            return -1;
        }
    }

    newProc->time = 0;

    spin_lock_irqsave(&lock, tmpFlags);

    list_add(&newProc->list, &procList);

    spin_unlock_irqrestore(&lock, tmpFlags);

    kfree(buf);

    buf = NULL;

    return count;
}


void timer_off(unsigned long obj){

    //pr_info("%lu\n",(jiffies/HZ));

    queue_work(workqueue, works);

    mod_timer(&timer, jiffies + (TIMEOUT_INTERVAL*HZ) );
}

void do_workqueue(struct work_struct *work){

    //pr_info("From Workqueue.\n");

    struct processInfo *currProc; // use as loop cursor
    struct processInfo *n; // temp storage for loop
    
    unsigned long tmpFlags;
    // unsigned long tmpTime;

    spin_lock_irqsave(&lock, tmpFlags);

      list_for_each_entry_safe(currProc, n, &procList, list){

        // currProc = list_entry(pos, struct processInfo, list);

   //      if(get_cpu_use(currProc->pid, &tmpTime) < 0){ //get unsuccessful
			// pr_info("PID:%lu NOTFOUND.",currProc->pid);
   //          list_del(&currProc->list);
   //          kfree(currProc);
	        
   //      }
   //      else{
   //          // print information to syslog for now.
   //          currProc->time += tmpTime;
   //          //pr_info("%lu: %lu", currProc->pid ,currProc->time);
   //      }
    }

    spin_unlock_irqrestore(&lock, tmpFlags);
  
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

    // initilize timer
    init_timer(&timer);
    timer.function = &timer_off;

    // set timer to go off every 5 sec
    mod_timer(&timer, jiffies + (TIMEOUT_INTERVAL*HZ) );

    // Create workqueue
    workqueue = alloc_workqueue("%s", WQ_MEM_RECLAIM, 1, "workqueue");

    if(!workqueue){
      pr_alert("Failed to create workqueue.\n");
      return -ENOMEM;
    }

    works = (struct work_struct *)kzalloc(sizeof(struct work_struct), GFP_KERNEL);

    if(!works){
      pr_alert("Failed to create work_struct.\n");
      return -ENOMEM;
    }

    INIT_WORK(works, do_workqueue);

    pr_alert("MP1 MODULE LOADED\n");

    return 0;   
}

// mp1_exit - Called when module is unloaded
void __exit mp1_exit(void)
{
    struct processInfo *currProc;
    struct processInfo *n;


    proc_remove(proc_dir_entry);
    proc_remove(proc_dir);

    // Delete timer
    del_timer_sync(&timer);

    // Delete list
    list_for_each_entry_safe(currProc, n, &procList, list){
      list_del(&currProc->list);
      kfree(currProc);
    }

    // Delete workqueue
    flush_workqueue(workqueue);
    destroy_workqueue(workqueue);

    kfree(works);

    pr_alert("MP1 MODULE UNLOADED\n");
}

// Register init and exit funtions
module_init(mp1_init);
module_exit(mp1_exit);

