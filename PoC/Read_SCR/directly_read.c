#include <linux/module.h>    // included for all kernel modules
#include <linux/kernel.h>    // included for KERN_INFO
#include <linux/init.h>      // included for __init and __exit macros
#include <asm/io.h>
#include <asm/sysreg.h>

MODULE_LICENSE("GPL");
MODULE_AUTHOR("Zhenyu Ning");
MODULE_DESCRIPTION("Read SCR directly with a kernel module running in non-secure state.");

static int __init directly_read_init(void) {
    uint32_t reg;

    // Directly read the SCR will fail since it is only accessible in secure state.
    // asm volatile("mrc p15, 0, %0, c1, c1, 0" : "=r" (reg));
    asm volatile("mrs %0, currentel" : "=r" (reg));
    printk(KERN_INFO "Current el: %x!\n", reg);

    // reg = read_sysreg_s(SYS_SD)
    // reg = read_scr_el3;
    asm volatile("mrs %0, scr_el3" : "=r" (reg));
    printk(KERN_INFO "SCR %x!\n", reg);
    // asm volatile("msr 0_c3_c2_0, R0");
    // reg = read_sysreg_s(SYS_DBGDTRRX_EL0);
    // 0xee100e15 <=> mrc p14, 0, R0, c0, c5, 0
    // asm volatile("mrs %0, "SYS_DBGDTRRX_EL0 "": "=r" (reg));
    // asm volatile("mrc p14, 0, R0, c0, c5, 0");
    return 0;
}

static void __exit directly_read_exit(void) {
    printk(KERN_INFO "Goodbye!\n");
}

module_init(directly_read_init);
module_exit(directly_read_exit);




