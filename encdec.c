#include <linux/ctype.h>
#include <linux/config.h>
#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/slab.h>
#include <linux/fs.h>
#include <linux/errno.h>
#include <linux/types.h>
#include <linux/proc_fs.h>
#include <linux/fcntl.h>
#include <asm/system.h>
#include <asm/uaccess.h>
#include <linux/string.h>

#include "encdec.h"

#define MODULE_NAME "encdec"

MODULE_LICENSE("GPL");
MODULE_AUTHOR("YOUR NAME");

int 	encdec_open(struct inode *inode, struct file *filp);
int 	encdec_release(struct inode *inode, struct file *filp);
int 	encdec_ioctl(struct inode *inode, struct file *filp, unsigned int cmd, unsigned long arg);

ssize_t encdec_read_caesar( struct file *filp, char *buf, size_t count, loff_t *f_pos );
ssize_t encdec_write_caesar(struct file *filp, const char *buf, size_t count, loff_t *f_pos);

ssize_t encdec_read_xor( struct file *filp, char *buf, size_t count, loff_t *f_pos );
ssize_t encdec_write_xor(struct file *filp, const char *buf, size_t count, loff_t *f_pos);

void ceaser_encrypt(char *s, unsigned char key);
void ceaser_decrypt(char *s, unsigned char key);
void xor_encrypt_decrypt(char *s, unsigned char key);

int memory_size= 0;

MODULE_PARM(memory_size, "i");

int major = 0;

char *ceaser_buffer, *xor_buffer; /*buffers*/

struct file_operations fops_caesar = {
	.open 	 =	encdec_open,
	.release =	encdec_release,
	.read 	 =	encdec_read_caesar,
	.write 	 =	encdec_write_caesar,
	.llseek  =	NULL,
	.ioctl 	 =	encdec_ioctl,
	.owner 	 =	THIS_MODULE
};

struct file_operations fops_xor = {
	.open 	 =	encdec_open,
	.release =	encdec_release,
	.read 	 =	encdec_read_xor,
	.write 	 =	encdec_write_xor,
	.llseek  =	NULL,
	.ioctl 	 =	encdec_ioctl,
	.owner 	 =	THIS_MODULE
};


// file-object's private data structure
typedef struct {
	unsigned char key;
	int read_state;
} encdec_private_date;

int init_module(void)
{
	major = register_chrdev(major, MODULE_NAME, &fops_caesar);
	if(major < 0)
	{
		return major;
	}

	// Allocated memory for the two device buffers using kmalloc (each of them should be of size 'memory_size')

	ceaser_buffer=kmalloc(memory_size, GFP_KERNEL);
	xor_buffer=kmalloc(memory_size, GFP_KERNEL); /*allocate memory to kernel space buffers*/

	if(!ceaser_buffer || !xor_buffer)
	{
        if (ceaser_buffer)
            kfree(ceaser_buffer);

        if (xor_buffer)
            kfree(xor_buffer);

	    unregister_chrdev(major, MODULE_NAME);
	    return -ENOMEM;
	}

	return 0;
}

void cleanup_module(void)
{
    unregister_chrdev(major, MODULE_NAME);
    kfree(ceaser_buffer);
    kfree(xor_buffer);
}

int encdec_open(struct inode *inode, struct file *filp)
{
	int minor = MINOR(inode->i_rdev);

	// 'filp->f_op' to the correct file-operations structure
	// Allocated memory for 'filp->private_data' (using kmalloc)

	if(minor==0)
        filp->f_op=&fops_caesar;
    else
        if(minor==1)
        filp->f_op=&fops_xor;
    else
        return -ENODEV;

    filp->private_data=kmalloc(sizeof(encdec_private_date), GFP_KERNEL);
    if(!filp->private_data)
        return -ENOMEM;

    ((encdec_private_date *)filp->private_data)->key = 0;
    ((encdec_private_date *)filp->private_data)->read_state = 0;

	return 0;
}

int encdec_release(struct inode *inode, struct file *filp)
{
	// Frees the allocated memory for 'filp->private_data' (kfree)

	kfree(filp->private_data);
	return 0;
}

int encdec_ioctl(struct inode *inode, struct file *filp, unsigned int cmd, unsigned long arg)
{
	// Updates the relevant fields in 'filp->private_data' according to the values of 'cmd' and 'arg'

	encdec_private_date *data = (encdec_private_date *)filp->private_data;

	switch(cmd)
	{
        case ENCDEC_CMD_CHANGE_KEY:
            data->key=(unsigned char)arg;
            break;

        case ENCDEC_CMD_SET_READ_STATE:
            data->read_state=(int)arg;
            break;

        case ENCDEC_CMD_ZERO:
            memset(ceaser_buffer,0, memory_size);
            memset(xor_buffer,0,memory_size);
            break;

        default:
            return -EINVAL;
	}
	return 0;
}

ssize_t encdec_read_caesar( struct file *filp, char *buf, size_t count, loff_t *f_pos )
{
    //Reads data from the caesar device buffer to user space

    encdec_private_date *data=(encdec_private_date*)filp->private_data;

    if (*f_pos>=memory_size)
        return 0; // End of buffer

    if (*f_pos+count>memory_size)
        count=memory_size- *f_pos; //reduce the count to not cross the buffer limit

    if (data->read_state==ENCDEC_READ_STATE_RAW)
    {
        if (copy_to_user(buf,ceaser_buffer+ *f_pos,count))
            return -EFAULT;
    }
    else
        if(data->read_state==ENCDEC_READ_STATE_DECRYPT)
        {
            char *decrypted_buf=kmalloc(count, GFP_KERNEL);
            if (!decrypted_buf)
            {
                return -ENOMEM;
            }
            memcpy(decrypted_buf,ceaser_buffer+ *f_pos,count);
            ceaser_decrypt(decrypted_buf,data->key);
            if (copy_to_user(buf,decrypted_buf,count))
            {
                kfree(decrypted_buf);
                return -EFAULT;
            }
        kfree(decrypted_buf);
    }
    *f_pos+=count;
    return count;
}

ssize_t encdec_write_caesar(struct file *filp, const char *buf, size_t count, loff_t *f_pos)
{
    //copies data from user space to the caesar device buffer

    encdec_private_date *data=(encdec_private_date *)filp->private_data;
    if (*f_pos>=memory_size)
        return -ENOSPC; //No space left on device

    if (*f_pos+count>memory_size)
        count=memory_size- *f_pos;  //reduce the count to not cross the buffer limit

    if (copy_from_user(ceaser_buffer+ *f_pos,buf,count))
        return -EFAULT;

    ceaser_encrypt(ceaser_buffer+ *f_pos,data->key);
    *f_pos+=count;
    return count;
}

ssize_t encdec_read_xor( struct file *filp, char *buf, size_t count, loff_t *f_pos )
{
    //Reads data from the XOR device buffer to user space

    encdec_private_date *data=(encdec_private_date*)filp->private_data;

    if (*f_pos>=memory_size)
        return 0; //End of buffer

    if (*f_pos+count > memory_size)
        count=memory_size- *f_pos; //reduce the count to not cross the buffer limit

    if (data->read_state==ENCDEC_READ_STATE_RAW)
    {
        if (copy_to_user(buf,xor_buffer+ *f_pos,count))
            return -EFAULT;
    }
    else
        if(data->read_state==ENCDEC_READ_STATE_DECRYPT)
        {
            char *decrypted_buf=kmalloc(count, GFP_KERNEL);
            if (!decrypted_buf)
                return -ENOMEM;

            memcpy(decrypted_buf,xor_buffer+ *f_pos,count);
            xor_encrypt_decrypt(decrypted_buf,data->key);
            if (copy_to_user(buf,decrypted_buf,count))
            {
                kfree(decrypted_buf);
                return -EFAULT;
            }
        kfree(decrypted_buf);
    }
    *f_pos+=count;
    return count;
}

ssize_t encdec_write_xor(struct file *filp, const char *buf, size_t count, loff_t *f_pos)
{
    //Transfers data from User Space to the XOR device buffer

    encdec_private_date *data = (encdec_private_date *)filp->private_data;
    if (*f_pos>=memory_size)
        return -ENOSPC; // No space left on device

    if (*f_pos+count>memory_size)
        count=memory_size- *f_pos;  //reduce the count to not cross the buffer limit

    if (copy_from_user(xor_buffer+ *f_pos,buf,count))
        return -EFAULT;

    xor_encrypt_decrypt(xor_buffer+ *f_pos,data->key);
    *f_pos+=count;
    return count;
}

void ceaser_encrypt(char *s, unsigned char key)
{
    int length=strlen(s), i;
    for (i=0; i<length; i++)
    {
        s[i]=(s[i]+key)%128;
    }
}

void ceaser_decrypt(char *s, unsigned char key)
{
    int length = strlen(s),i;
    for (i=0; i<length; i++)
    {
        s[i]=((s[i]-key)+128)%128;
    }
}

void xor_encrypt_decrypt(char *s, unsigned char key)
{
    int length=strlen(s),i;
    for (i = 0; i<length; i++)
    {
        s[i]^=key;
    }
}
