#ifndef ROOTKIT_H

#define ROOTKIT_H

static ssize_t mp1_read(struct file *file, char __user *buffer, size_t count, loff_t *data);

static ssize_t mp1_write(struct file *file, const char __user *buffer, size_t count, loff_t *data);

void timer_off(unsigned long obj);

void do_workqueue(struct work_struct *work);

#endif //ROOTKIT_H