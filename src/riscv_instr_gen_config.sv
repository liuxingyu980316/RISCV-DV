/*
 * Copyright 2018 Google LLC
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

//-----------------------------------------------------------------------------
// RISC-V assembly program generator configuration class  配置
//-----------------------------------------------------------------------------

class riscv_instr_gen_config extends uvm_object;

  //-----------------------------------------------------------------------------
  // Random instruction generation settings
  //-----------------------------------------------------------------------------

  // Instruction count of the main program       主程序的指令数
  rand int               main_program_instr_cnt;

  // Instruction count of each sub-program       子程序的指令数
  rand int               sub_program_instr_cnt[];

  // Instruction count of the debug rom         调试 rom的指令数
  rand int               debug_program_instr_cnt;

  // Instruction count of debug sub-programs    调试子程序的指令数
  rand int               debug_sub_program_instr_cnt[];

  // Pattern of data section: RAND_DATA, ALL_ZERO, INCR_VAL  数据段的模式 随机 全零 递增
  rand data_pattern_t    data_page_pattern;

  // Initialization of the vregs  初始化vreg是指向量寄存器
  // SAME_VALUES_ALL_ELEMS - Using vmv.v.x to fill all the elements of the vreg with the same value as the one in the GPR selected   vreg的元素填充为与所选通用寄存器（GPR）中相同的值，通常用于测试程序在处理重复输入时的行为，或者用于重置或初始化vreg的内容
  // RANDOM_VALUES_VMV     - Using vmv.v.x + vslide1up.vx to randomize the contents of each vector element    vmv.v.x指令和vslide1up.vx指令的组合来随机化每个矢量元素的内容。这种初始化模式通常用于模拟真实环境中的随机数据，以测试程序在处理随机输入时的行为
  // RANDOM_VALUES_LOAD    - Using vle.v, same approach as RANDOM_VALUES_VMV but more efficient for big VLEN   使用vle.v指令来加载随机化的数据到vreg中。这种初始化模式与RANDOM_VALUES_VMV相同，但更适合于处理大的向量长度（VLEN），因为它可以更高效地加载数据到vreg中
  
  vreg_init_method_t     vreg_init_method = RANDOM_VALUES_VMV;    // 默认的向量寄存器的初始化是随机的模式

  // Associate array for delegation configuration for each exception and interrupt    用于每个异常和中断的委托配置的关联数组  用于表示委托是否被启用（1表示启用，0表示禁用）
  // When the bit is 1, the corresponding delegation is enabled.    当位为1时，相应的委托被启用。 在计算机科学和编程中，委托是指将某个任务或操作的执行权力交给另一个实体或模块的行为。在异常和中断处理中，委托通常涉及到将异常或中断的处理权力交给不同的模式（如机器模式或用户模式）或不同的处理程序。
  rand bit               m_mode_exception_delegation[exception_cause_t];  用于配置机器模式（M-mode）异常
  rand bit               s_mode_exception_delegation[exception_cause_t];  监督模式（S-mode）异常
  rand bit               m_mode_interrupt_delegation[interrupt_cause_t];  用于配置机器模式（M-mode）中断
  rand bit               s_mode_interrupt_delegation[interrupt_cause_t];  监督模式（S-mode）中断

  // Priviledged mode after boot  可以在测试或模拟中随机生成不同的特权模式和寄存器设置，以测试程序在不同特权模式下的行为。
  // 特权模式是指操作系统或内核拥有的特殊权限和访问级别,在RISC-V架构中，特权模式分为不同的级别，如机器模式（M-mode）、监督模式（S-mode）和用户模式（U-mode）    USER_MODE = 0b00 SUPERVISOR_MODE = 0b01  RESERVED_MODE = 0b10
  rand privileged_mode_t init_privileged_mode;

  rand bit[XLEN-1:0]     mstatus, mie,    // 表示不同特权模式下的状态和控制寄存器
                         sstatus, sie,
                         ustatus, uie;

  // Key fields in xSTATUS
  // Memory protection bits   用于存储有关处理器状态和异常处理的信息
  rand bit               mstatus_mprv;   // 该位表示是否启用内存保护。当设置为1时，内存保护被启用，处理器将执行内存访问权限检查。进入内存
  rand bit               mstatus_mxr;    // 该位表示是否启用内存执行权限。当设置为1时，处理器将禁止执行从内存中获取的指令。 内存中执行指令
  rand bit               mstatus_sum;    // 该位表示是否启用用户模式下的内存保护。当设置为1时，用户模式下的内存保护被启用。   确保只使用有权限的内存部分
  rand bit               mstatus_tvm;    // 该位表示是否启用陷阱向量模式。当设置为1时，处理器将使用陷阱向量表来处理异常和中断。
  rand bit [1:0]         mstatus_fs;     // 这两个字段分别表示浮点状态的模式。它们用于控制处理器中的浮点操作的行为。
  rand bit [1:0]         mstatus_vs;     // 这两个字段分别表示向量状态的模式。它们用于控制处理器中向量操作的行为。
  rand mtvec_mode_t      mtvec_mode;     // 该字段表示陷阱向量表的模式。它用于控制处理器如何访问和处理异常和中断的陷阱向量. 不同的方式解决异常和中断

  // TVEC alignment                 根据RISC-V特权规范，默认将设置为2（4字节对齐） 
  // This value is the log_2 of the byte-alignment of TVEC.BASE field      对齐是指将数据存储在内存中的特定地址，以便于处理器更高效地访问和操作。对齐通常是以2的幂为单位的，比如4字节对齐、8字节对齐等
  // As per RISC-V privileged spec, default will be set to 2 (4-byte aligned)       通过使用这个随机变量，可以在测试或模拟中随机生成不同的陷阱向量表对齐方式，以测试程序在不同对齐设置下的行为。
  rand int tvec_alignment = 2; 

  // Floating point rounding mode     浮点舍入的模式
  rand f_rounding_mode_t fcsr_rm;   //  舍入到最接近的值    向零方向舍入      向下舍入

  // Enable sfence.vma instruction         负责在操作系统修改内存映射表后，打扫和更新处理器的“记忆”，确保处理器使用的内存映射信息是最新的
  rand bit               enable_sfence;   //  确保内存访问的一致性和正确性

  // Reserved register
  // Reserved for various hardcoded routines    这些寄存器被保留，用于各种硬编码例程的执行。 在程序中有特定的作用，被预留给特定的例程使用。不能被随意改变或用于其他目的
  rand riscv_reg_t       gpr[4];
  
  // Used by any DCSR operations inside of the debug rom.
  // Also used by the PMP generation.         同上，预留的一个CSR寄存器
  rand riscv_reg_t       scratch_reg;           
  
  // Reg used exclusively by the PMP exception handling routine.
  // Can overlap with the other GPRs used in the random generation,
  // as PMP exception handler is hardcoded and does not include any
  // random instructions.               
  rand riscv_reg_t       pmp_reg[2];                //   由PMP异常处理例程专用的寄存器
  // Use a random register for stack pointer/thread pointer
  rand riscv_reg_t       sp;       // 存储堆栈指针
  rand riscv_reg_t       tp;       // 线程指针
  rand riscv_reg_t       ra;       // 返回地址

  // Options for privileged mode CSR checking
  // Below checking can be made optional as the ISS implementation could be different with the
  // processor.
  bit                    check_misa_init_val = 1'b0;     // 用于控制特权模式下CSR检查的选项
  bit                    check_xstatus = 1'b1;           //  用于控制是否检查XSTATUS寄存器的值

  // Virtual address translation is on for this test
  rand bit               virtual_addr_translation_on;     //  是否启用，虚拟地址转换是一种将程序使用的虚拟地址转换为实际物理地址的技术

  // Vector extension setting
  rand riscv_vector_cfg  vector_cfg;           // 是否启用向量拓展， 一次性地对多个向量进行运算，向量扩展还提供了一些特殊的函数，比如点积、叉积、矩阵乘法等等，这些函数可以大大简化向量的运算

  // PMP configuration settings         // 是否启动PMP（Physical Memory Protection，物理内存保护）
  rand riscv_pmp_cfg pmp_cfg;

  //-----------------------------------------------------------------------------
  //  User space memory region and stack setting
  //  用户空间内存区域和堆栈设置
  //  在RISC-V架构中，用户空间内存区域和堆栈设置可以通过配置相关的寄存器和内存映射表来实现。
  //  这些配置可以定义用户空间内存区域的起始地址和大小，以及堆栈的起始地址和大小等。
  //-----------------------------------------------------------------------------

  mem_region_t mem_region[$] = '{   //  mem_region定义了两个内存区域，分别为region_0和region_1。
        //    其中，region_0的大小为4096字节，region_1的大小为4096乘以16字节，也就是64KB。xwr表示该内存区域的访问权限，3'b111表示读、写和执行权限都被允许。
    '{name:"region_0", size_in_bytes: 4096,      xwr: 3'b111},
    '{name:"region_1", size_in_bytes: 4096 * 16, xwr: 3'b111}
  };

  // Dedicated shared memory region for multi-harts atomic operations
  //  amo_region定义了一个名为amo_0的内存区域，大小为64字节，xwr同样为3'b111，表示读、写和执行权限都被允许。这个内存区域被用来进行多核之间的原子操作。
  mem_region_t amo_region[$] = '{
    '{name:"amo_0",    size_in_bytes: 64,        xwr: 3'b111}
  };

  // Stack section word length
  // stack_len定义了一个整数类型的变量，表示堆栈的长度为5000个字
  int stack_len = 5000;

  //-----------------------------------------------------------------------------
  // Kernel section setting, used by supervisor mode programs
  // 内核段设置，由监督模式程序使用
  // 监督模式程序是指运行在RISC-V架构的监督模式下的程序，具有访问和控制系统资源的权限。内核段设置对监督模式程序来说是重要的，因为它决定了内核代码和数据在内存中的位置和访问权限。
  //-----------------------------------------------------------------------------

  mem_region_t s_mem_region[$] = '{
    // 内核内存的大小
    '{name:"s_region_0", size_in_bytes: 4096, xwr: 3'b111},
    '{name:"s_region_1", size_in_bytes: 4096, xwr: 3'b111}};

  // Kernel Stack section word length
     // 内核堆栈的大小
  int kernel_stack_len = 4000;

  // Number of instructions for each kernel program
  int kernel_program_instr_cnt = 400;    //  每个内核程序的指令数量为400条 
 
  // Queue of all the main implemented CSRs that the boot privilege mode cannot access
  // e.g. these CSRs are in higher privilege modes - access should raise an exception
  privileged_reg_t       invalid_priv_mode_csrs[$];   //   用于存储所有在启动特权模式下无法访问的主要实现的CSR（控制和状态寄存器）。这些CSR处于更高的特权模式下，如果尝试访问它们应该会引发异常。

  //-----------------------------------------------------------------------------
  // Command line options or control knobs
  // 命令行选项或控制
  //-----------------------------------------------------------------------------
  // Main options for RISC-V assembly program generation
  // Number of sub-programs per test
  int                    num_of_sub_program = 5;        //  控制生成的RISC-V汇编程序中子程序的数量
  int                    instr_cnt = 200;               //  表示每个子程序的指令数量为200条
  int                    num_of_tests = 1;              //  表示生成的RISC-V汇编程序的测试数量为1个
  // For tests doesn't involve load/store, the data section generation could be skipped
  bit                    no_data_page;                  //  有些测试可能不涉及加载/存储操作,将no_data_page设置为1，以跳过数据页的生成
  // Options to turn off some specific types of instructions
  bit                    no_branch_jump;     // No branch/jump instruction     用于控制是否禁用分支/跳转指令
  bit                    no_load_store;      // No load/store instruction      控制是否禁用加载/存储指令
  bit                    no_csr_instr;       // No csr instruction             是否禁用CSR（控制和状态寄存器）指令
  bit                    no_ebreak = 1;      // No ebreak instruction          是否禁用ebreak指令， ebreak指令用于触发处理器的异常处理机制，默认禁用
  // Only enable ecall if you have overriden the test_done mechanism.
  bit                    no_ecall = 1;       // No ecall instruction           是否禁用ecall指令。ecall指令用于触发处理器的系统调用机制，例如调用操作系统的服务。
  bit                    no_dret = 1;        // No dret instruction            用于控制是否禁用dret指令。dret指令用于从调试异常中返回。如果禁用dret指令，程序将无法从调试异常中返回。
  bit                    no_fence;           // No fence instruction           用于控制是否禁用fence指令。fence指令用于在内存操作之间插入一个屏障，以确保内存操作的顺序性。如果禁用fence指令，程序将无法保证内存操作的顺序性
  bit                    no_wfi = 1;         // No WFI instruction             是否禁用WFI（Wait For Interrupt）指令。WFI指令用于使处理器进入低功耗模式，等待中断的发生。如果禁用WFI指令，程序将无法使处理器进入低功耗模式。
  bit                    enable_unaligned_load_store;                          控制是否启用非对齐的加载/存储操作。在RISC-V架构中，非对齐的加载/存储操作可能会导致异常或错误的行为。如果启用非对齐的加载/存储操作，程序将可以尝试进行非对齐的内存访问。
  int                    illegal_instr_ratio;                                  用于控制生成的RISC-V汇编程序中非法指令的比例。非法指令是指RISC-V架构不支持的指令。通过调整非法指令的比例，可以测试程序在处理非法指令时的行为和性能。
  int                    hint_instr_ratio;                                     控制生成的RISC-V汇编程序中提示指令的比例。提示指令是一种对处理器性能有影响的指令，但不一定会改变程序的行为。通过调整提示指令的比例，可以测试程序在不同提示指令下的性能和行为。
  // CSR instruction control
  bit                    gen_all_csrs_by_default = 0; // Generate CSR instructions that use all supported CSRs. Other options below only take effect if this is enabled.
                                                      // 用于控制是否默认生成使用所有支持的CSR的CSR指令。如果启用这个选项，程序将生成使用所有支持的CSR的CSR指令
  bit                    gen_csr_ro_write = 0;        // Generate CSR writes to read-only CSRs   用于控制是否生成对只读CSR的写操作。在RISC-V架构中，有些CSR是只读的，不允许写操作。如果启用这个选项，程序将尝试生成对只读CSR的写操作
  privileged_reg_t       add_csr_write[] = {};        // CSRs to add to the set of writeable CSRs   是一个队列，用于添加可写CSR。通过向这个队列中添加CSR，可以生成对这些CSR的写操作。
  privileged_reg_t       remove_csr_write[] = {};     // CSRs to remove from the set of writeable CSRs    是一个队列，用于从可写CSR中移除CSR。通过向这个队列中添加CSR，可以禁止生成对这些CSR的写操作。
  // Number of harts to be simulated, must be <= NUM_HARTS   // 控制在模拟中运行的RISC-V硬件线程（hart）的数量
  int                    num_of_harts = NUM_HARTS;
  // Use SP as stack pointer
  bit                    fix_sp;                       // 用于控制是否将SP（Stack Pointer）寄存器用作堆栈指针。 在测试或模拟中，可能需要固定使用SP寄存器以确保程序的正确性和一致性。此外，在某些嵌入式系统中，可能也需要固定使用SP寄存器以满足特定的硬件要求。
  // Use push/pop section for data pages
  bit                    use_push_data_section = 0;    // 用于控制是否使用push/pop段来生成数据页。在生成数据页时，有两种不同的方法：一种是使用直接的数据声明和定义，另一种是使用push/pop段。
  // Directed boot privileged mode, u, m, s
  string                 boot_mode_opts;             // 可以指定在启动时使用哪种特权模式。
  int                    enable_page_table_exception;  //  用于控制是否启用页表异常,用于处理内存访问时的页表错误
  bit                    no_directed_instr;         // 用于控制是否禁用定向指令 
  // A name suffix for the generated assembly program  // 用于为生成的汇编程序指定一个后缀名
  string                 asm_test_suffix;
  // Enable interrupt bit in MSTATUS (MIE, SIE, UIE)
  bit                    enable_interrupt;          //  用于控制是否启用中断
  bit                    enable_nested_interrupt;   //  变量用于控制是否启用嵌套中断。嵌套中断是指在处理一个中断的过程中，又发生了另一个中断。
  // We need a separate control knob for enabling timer interrupts, as Spike
  // throws an exception if xIE.xTIE is enabled       //  控制是否启用定时器中断
  bit                    enable_timer_irq;
  // Generate a bare program without any init/exit/error handling/page table routines
  // The generated program can be integrated with a larger program.
  // Note that the bare mode program is not expected to run in standalone mode   用于控制是否生成一个裸程序，这个程序中只包含了最基本的指令和数据，没有任何额外的处理代码。裸程序不能独立运行，必须被嵌入到一个完整的程序中才能执行。
  bit                    bare_program_mode;
  // Enable accessing illegal CSR instruction
  // - Accessing non-existence CSR
  // - Accessing CSR with wrong privileged mode
  bit                    enable_illegal_csr_instruction;    // 控制是否允许访问非法的CSR指令,比如访问不存在的CSR或者在不正确的特权模式下访问CSR
  // Enable accessing CSRs at an invalid privilege level
  bit                    enable_access_invalid_csr_level;
  // Enable misaligned instruction (caused by JALR instruction)    // 控制是否允许在无效的特权级别下访问CSR.可以允许在无效的特权级别下访问CSR。这样，程序可以执行一些特殊的操作，比如测试处理器的边界条件或者调试目的
  bit                    enable_misaligned_instr;
  // Enable some dummy writes to main system CSRs (xSTATUS/xIE) at beginning of test   // 用于控制在测试开始时是否对一些主要的系统CSR（xSTATUS/xIE）进行一些虚拟的写入操作
  // to check repeated writes
  bit                    enable_dummy_csr_write;
  bit                    randomize_csr = 0;
  // sfence support
  bit                    allow_sfence_exception = 0;   // 控制是否允许sfence指令产生异常。sfence指令可能会产生异常，比如无效的页表项或者访问权限错误等。
  // Interrupt/Exception Delegation
  bit                    no_delegation = 1;             // 用于控制是否禁用中断/异常委派。在RISC-V架构中，中断/异常委派是一种机制，允许低特权级别的程序处理某些中断/异常。通过将no_delegation设置为1，可以禁用中断/异常委派，使得所有的中断/异常都由最高特权级别的程序处理
  bit                    force_m_delegation = 0;        // 用于强制将中断/异常委派给机器模式（M）和监督模式（S）。通过将这两个变量设置为1，可以强制将所有的中断/异常都委派给机器模式（M）或监督模式（S）处理，即使某些中断/异常本来应该由更低特权级别的程序处理。
  bit                    force_s_delegation = 0;        // 同上
  bit                    support_supervisor_mode;       // 用于控制是否支持监督模式（S）
  bit                    disable_compressed_instr;      // 控制是否禁用压缩指令
  // "Memory mapped" address that when written to will indicate some event to    // 用于控制RISC-V汇编程序中一个特殊的“内存映射”地址的行为
  // the testbench - testbench will take action based on the value written
  bit [XLEN - 1 : 0]     signature_addr = 32'hdead_beef;           //   这个地址被用作一个特殊的标记，当程序向这个地址写入数据时，会触发一些事件或行为
  bit                    require_signature_addr = 1'b0;            //   用于控制是否需要在程序中强制使用signature_addr,用来确保程序在某些关键点上执行了预期的操作
  // Enable a full or empty debug_rom section. 
  // Full debug_rom will contain random instruction streams.
  // Empty debug_rom will contain just dret instruction and will return immediately.  在RISC-V汇编程序中，debug_rom段是一个特殊的代码段，用于存储调试相关的指令和数据。当程序执行到这个段时，会执行其中的指令并返回结果。
  // Will be empty by default.        用于控制是否生成一个完整的或空的debug_rom段。
  bit                    gen_debug_section = 1'b0;
  // Enable generation of a directed sequence of instructions containing
  // ebreak inside the debug_rom.       在RISC-V架构中，ebreak指令是一个特殊的指令，用于触发一个异常或中断。当程序执行到这个指令时，会跳转到异常处理程序并执行相应的操作。
  // Disabled by default.
  bit                    enable_ebreak_in_debug_rom = 1'b0;
  // Enable setting dcsr.ebreak(m/s/u)
  bit                    set_dcsr_ebreak = 1'b0;    // set_dcsr_ebreak，用于控制是否设置dcsr寄存器的ebreak位。中断异常位
  // Number of sub programs in the debug rom         用于控制在debug_rom段中生成的子程序（sub program）的数量。
  int                    num_debug_sub_program = 0;
  // Enable debug single stepping                  //  是否启动单步调试
  bit                    enable_debug_single_step = 0;
  // Number of single stepping iterations
  rand int               single_step_iterations;     // 单步调试时每一步执行的指令数量
  // Enable mstatus.tw bit - causes u-mode WFI to raise illegal instruction exceptions
  bit                    set_mstatus_tw;            //   mstatus寄存器是一个用于控制处理器状态的特殊寄存器,当tw位被设置为1时，用户模式下的WFI（wait for interrupt 等着什么都不干）指令会触发一个非法指令异常；当tw位被设置为0时，用户模式下的WFI指令会正常执行，不会触发任何异常
  // Enable users to set mstatus.mprv to enable privilege checks on memory accesses.  // 当mprv位被设置为1时，会启用内存访问的权限检查，即程序在访问内存时需要满足相应的权限要求；当mprv位被设置为0时，不会启用内存访问的权限检查，程序可以自由地访问内存。
  bit                    set_mstatus_mprv;         //  mstatus寄存器是一个用于控制处理器状态的特殊寄存器。其中的mprv位是一个标志位，用于控制是否启用内存访问的权限检查。
  // Stack space allocated to each program, need to be enough to store necessary context
  // Example: RA, SP, T0
  int                    min_stack_len_per_program = 10 * (XLEN/8);
  int                    max_stack_len_per_program = 16 * (XLEN/8);    // 这意味着每个程序在执行时至少需要分配字节的栈空间来存储必要的上下文信息。以避免栈溢出和内存泄漏
  // Maximum branch distance, avoid skipping large portion of the code
  int                    max_branch_step = 20;            // 用于控制程序执行时的最大分支步长.表示程序在执行时允许的最大分支步长为20个指令。分支跳转指令：jal、jalr、beq
  // Maximum directed instruction stream sequence count
  int                    max_directed_instr_stream_seq = 20;   // 执行时的最大指令流序列计数,一组连续的指令，它们按照顺序执行并且没有任何分支或跳转
  // Reserved registers    用于存储RISC-V架构中保留的寄存器
  // 在RISC-V架构中，有一些特殊的寄存器被保留用于特定的用途，例如zero、ra、sp、gp、tp、t0、t1、t2、s0、s1等。这些寄存器在程序执行过程中扮演着重要的角色，不能被普通的指令修改或访问。程序初始化时可以将它们的值预加载到reserved_regs数组,后续直接使用即可
  riscv_reg_t            reserved_regs[];
  // Floating point support
  bit                    enable_floating_point;     // 用于控制是否启用RISC-V架构中的浮点支持
  // Vector extension support
  bit                    enable_vector_extension;   // 控制是否启用RISC-V架构中的向量扩展支持。
  // Only generate vector instructions
  bit                    vector_instr_only;         //  控制是否只生成向量指令
  // Bit manipulation extension support
  bit                    enable_b_extension;

  bit                    enable_zba_extension;      // 控制是否支持位拓展
  bit                    enable_zbb_extension;
  bit                    enable_zbc_extension;
  bit                    enable_zbs_extension;

  b_ext_group_t          enable_bitmanip_groups[] = {ZBB, ZBS, ZBP, ZBE, ZBF, ZBC, ZBR, ZBM, ZBT,
                                                     ZB_TMP};
  // ZBB：位块复制（Bit Block Copy）指令组，用于复制一个位块到另一个位块。
  // ZBS：位块设置（Bit Block Set）指令组，用于设置一个位块中的所有位为1。
  // ZBP：位块反转（Bit Block Inverse）指令组，用于反转一个位块中的所有位。
  // ZBE：位块清除（Bit Block Clear）指令组，用于清除一个位块中的所有位。
  // ZBF：位块查找（Bit Block Find）指令组，用于在一个位块中查找第一个设置的位。
  // ZBC：位块计数（Bit Block Count）指令组，用于统计一个位块中设置的位的数量。
  // ZBR：位块反转并复制（Bit Block Reverse and Copy）指令组，用于反转并复制一个位块。
  // ZBM：位块合并（Bit Block Merge）指令组，用于合并两个位块。
  // ZBT：位块测试（Bit Block Test）指令组，用于测试一个位块中的特定位。
  // ZB_TMP：临时位操作扩展指令组，用于存储临时的位操作扩展指令。

  //-----------------------------------------------------------------------------
  // Command line options for instruction distribution control
  //-----------------------------------------------------------------------------
  int                    dist_control_mode;    //   控制指令分布的控制模式和每个指令类别的分布比例  均匀分布 正态分布  自定义分布
  int unsigned           category_dist[riscv_instr_category_t]; category_dist数组用于存储每个指令类别的分布比例

  // 假设riscv_instr_category_t枚举类型定义了以下指令类别：
  // typedef enum {  
  // RISCV_INSTR_CATEGORY_LOAD,  
  // RISCV_INSTR_CATEGORY_STORE,  
  // RISCV_INSTR_CATEGORY_BRANCH,  
  // } riscv_instr_category_t;
  
  // int unsigned category_dist[riscv_instr_category_t] = {  
  // 2,                 // LOAD    权重为2
  // 2,                 // STORE   权重为2
  // 1,                 // BRANCH  权重为1
  // };

  constraint default_c {
    sub_program_instr_cnt.size() == num_of_sub_program;                  // 子程序的数量，默认5
    debug_sub_program_instr_cnt.size() == num_debug_sub_program;         // debug下的子程序的数量，默认0
    main_program_instr_cnt inside {[10 : instr_cnt]};      // 每个子程序的指令数量，默认 10 - 100 
    foreach(sub_program_instr_cnt[i]) {
      sub_program_instr_cnt[i] inside {[10 : instr_cnt]};  // 每个debug子程序的指令数量，默认 10 - 100 
    }
    // Disable sfence if the program is not boot to supervisor mode
    // If sfence exception is allowed, we can enable sfence instruction in any priviledged mode.
    // When MSTATUS.TVM is set, executing sfence.vma will be treate as illegal instruction
      if(allow_sfence_exception) {             //是否允许sfence指令产生异常
      enable_sfence == 1'b1;                   // 打开 sfence异常的产生
        (init_privileged_mode != SUPERVISOR_MODE) || (mstatus_tvm == 1'b1);    //  在任何特权模式下启用 sfence 指令
      } else {             //   MSTATUS.TVM 被设置时，执行 sfence.vma 将被视为非法指令
      (init_privileged_mode != SUPERVISOR_MODE || !riscv_instr_pkg::support_sfence || mstatus_tvm
          || no_fence) -> (enable_sfence == 1'b0);
    }
  }

  constraint debug_mode_c {
      if (riscv_instr_pkg::support_debug_mode) {
        debug_program_instr_cnt inside {[100 : 300]};
        foreach(debug_sub_program_instr_cnt[i]) {
          debug_sub_program_instr_cnt[i] inside {[100 : 300]};
        }
      }
    `ifndef DSIM
       main_program_instr_cnt + sub_program_instr_cnt.sum() == instr_cnt;
    `else
       // dsim has some issue supporting sum(), use some approximate constraint to generate
       // instruction cnt
       if (num_of_sub_program > 0) {
         main_program_instr_cnt inside {[10:instr_cnt/2]};
         foreach (sub_program_instr_cnt[i]) {
           sub_program_instr_cnt[i] inside {[10:instr_cnt/num_of_sub_program]};
         }
       } else {
         main_program_instr_cnt == instr_cnt;
       }
    `endif
  }

  // Keep the number of single step iterations relatively small
  constraint debug_single_step_c {
    if (enable_debug_single_step) {
      single_step_iterations inside {[10 : 50]};  // 单步调试的时候每一个步里面的指令数量
    }
  }

  // Boot privileged mode distribution
  constraint boot_privileged_mode_dist_c {
    // Boot to higher privileged mode more often
    if(riscv_instr_pkg::supported_privileged_mode.size() == 2) {
      init_privileged_mode dist {riscv_instr_pkg::supported_privileged_mode[0] := 6,
                                 riscv_instr_pkg::supported_privileged_mode[1] := 4};
    } else if (riscv_instr_pkg::supported_privileged_mode.size() == 3) {
      init_privileged_mode dist {riscv_instr_pkg::supported_privileged_mode[0] := 4,
                                 riscv_instr_pkg::supported_privileged_mode[1] := 3,
                                 riscv_instr_pkg::supported_privileged_mode[2] := 3};
    } else {
      init_privileged_mode == riscv_instr_pkg::supported_privileged_mode[0];
    }
  }

  constraint mtvec_c {
    mtvec_mode inside {supported_interrupt_mode};
    if (mtvec_mode == DIRECT) {
     soft tvec_alignment == 2;
    } else {
     // Setting MODE = Vectored may impose an additional alignmentconstraint on BASE,
     // requiring up to 4×XLEN-byte alignment
     soft tvec_alignment == $clog2((XLEN * 4) / 8);
    }
  }

  constraint mstatus_c {
    if (set_mstatus_mprv) {
      mstatus_mprv == 1'b1;
    } else {
      mstatus_mprv == 1'b0;
    }
    if (SATP_MODE == BARE) {
      mstatus_mxr == 0;
      mstatus_sum == 0;
      mstatus_tvm == 0;
    }
  }

  // Exception delegation setting
  constraint exception_delegation_c {
    // Do not delegate instructino page fault to supervisor/user mode because this may introduce
    // dead loop. All the subsequent instruction fetches may fail and program cannot recover.
    m_mode_exception_delegation[INSTRUCTION_PAGE_FAULT] == 1'b0;
    if(force_m_delegation) {
      foreach(m_mode_exception_delegation[i]) {
        soft m_mode_exception_delegation[i] == 1'b1;
      }
      foreach(m_mode_interrupt_delegation[i]) {
        soft m_mode_interrupt_delegation[i] == 1'b1;
      }
    }
    if(force_s_delegation) {
      foreach(s_mode_exception_delegation[i]) {
        soft s_mode_exception_delegation[i] == 1'b1;
      }
      foreach(s_mode_interrupt_delegation[i]) {
        soft s_mode_interrupt_delegation[i] == 1'b1;
      }
    }
  }

  // Spike only supports a subset of exception and interrupt delegation
  // You can modify this constraint if your ISS support different set of delegations
  constraint delegation_c {
    foreach(m_mode_exception_delegation[i]) {
      if(!support_supervisor_mode || no_delegation) {
        m_mode_exception_delegation[i] == 0;
      }
      if(!(i inside {INSTRUCTION_ADDRESS_MISALIGNED, BREAKPOINT, ECALL_UMODE,
                     INSTRUCTION_PAGE_FAULT, LOAD_PAGE_FAULT, STORE_AMO_PAGE_FAULT})) {
        m_mode_exception_delegation[i] == 0;
      }
    }
    foreach(m_mode_interrupt_delegation[i]) {
      if(!support_supervisor_mode || no_delegation) {
        m_mode_interrupt_delegation[i] == 0;
      }
      if(!(i inside {S_SOFTWARE_INTR, S_TIMER_INTR, S_EXTERNAL_INTR})) {
        m_mode_interrupt_delegation[i] == 0;
      }
    }
  }

  constraint ra_c {
    ra dist {RA := 3, T1 := 2, [SP:T0] :/ 1, [T2:T6] :/ 4};
    ra != sp;
    ra != tp;
    ra != ZERO;
  }

  constraint sp_tp_c {
    if (fix_sp) {
      sp == SP;
    }
    sp != tp;
    !(sp inside {GP, RA, ZERO});
    !(tp inside {GP, RA, ZERO});
  }

  // This reg is used in various places throughout the generator,
  // so need more conservative constraints on it.
  constraint reserve_scratch_reg_c {
    !(scratch_reg inside {ZERO, sp, tp, ra, GP});
  }

  // These registers is only used inside PMP exception routine,
  // so we can be a bit looser with constraints.
  constraint reserve_pmp_reg_c {
    foreach (pmp_reg[i]) {
      !(pmp_reg[i] inside {ZERO, sp, tp, scratch_reg});
    }
    unique {pmp_reg};
  }

  constraint gpr_c {
    foreach (gpr[i]) {
      !(gpr[i] inside {sp, tp, scratch_reg, pmp_reg, ZERO, RA, GP});
    }
    unique {gpr};
  }

  constraint addr_translaction_rnd_order_c {
    solve init_privileged_mode before virtual_addr_translation_on;
  }

  constraint addr_translaction_c {
    if ((init_privileged_mode != MACHINE_MODE) && (SATP_MODE != BARE)) {
      virtual_addr_translation_on == 1'b1;
    } else {
      virtual_addr_translation_on == 1'b0;
    }
  }

  constraint floating_point_c {
    if (enable_floating_point) {
      mstatus_fs == 2'b01;
    } else {
      mstatus_fs == 2'b00;
    }
  }

  constraint mstatus_vs_c {
    if (enable_vector_extension) {
      mstatus_vs == 2'b01;
    } else {
      mstatus_vs == 2'b00;
    }
  }

  `uvm_object_utils_begin(riscv_instr_gen_config)
    `uvm_field_int(main_program_instr_cnt, UVM_DEFAULT)
    `uvm_field_sarray_int(sub_program_instr_cnt, UVM_DEFAULT)
    `uvm_field_int(debug_program_instr_cnt, UVM_DEFAULT)
    `uvm_field_enum(data_pattern_t, data_page_pattern, UVM_DEFAULT)
    `uvm_field_enum(privileged_mode_t, init_privileged_mode, UVM_DEFAULT)
    `uvm_field_array_enum(riscv_reg_t, reserved_regs, UVM_DEFAULT)
    `uvm_field_enum(riscv_reg_t, ra, UVM_DEFAULT)
    `uvm_field_enum(riscv_reg_t, sp, UVM_DEFAULT)
    `uvm_field_enum(riscv_reg_t, tp, UVM_DEFAULT)
    `uvm_field_int(tvec_alignment, UVM_DEFAULT)
    `uvm_field_int(no_data_page, UVM_DEFAULT)
    `uvm_field_int(no_branch_jump, UVM_DEFAULT)
    `uvm_field_int(no_load_store, UVM_DEFAULT)
    `uvm_field_int(no_csr_instr, UVM_DEFAULT)
    `uvm_field_int(no_ebreak, UVM_DEFAULT)
    `uvm_field_int(no_ecall, UVM_DEFAULT)
    `uvm_field_int(no_dret, UVM_DEFAULT)
    `uvm_field_int(no_fence, UVM_DEFAULT)
    `uvm_field_int(no_wfi, UVM_DEFAULT)
    `uvm_field_int(fix_sp, UVM_DEFAULT)
    `uvm_field_int(enable_unaligned_load_store, UVM_DEFAULT)
    `uvm_field_int(illegal_instr_ratio, UVM_DEFAULT)
    `uvm_field_int(hint_instr_ratio, UVM_DEFAULT)
    `uvm_field_int(gen_all_csrs_by_default, UVM_DEFAULT)
    `uvm_field_int(gen_csr_ro_write, UVM_DEFAULT)
    `uvm_field_array_enum(privileged_reg_t, add_csr_write, UVM_DEFAULT)
    `uvm_field_array_enum(privileged_reg_t, remove_csr_write, UVM_DEFAULT)
    `uvm_field_string(boot_mode_opts, UVM_DEFAULT)
    `uvm_field_int(enable_page_table_exception, UVM_DEFAULT)
    `uvm_field_int(no_directed_instr, UVM_DEFAULT)
    `uvm_field_int(enable_interrupt, UVM_DEFAULT)
    `uvm_field_int(enable_timer_irq, UVM_DEFAULT)
    `uvm_field_int(bare_program_mode, UVM_DEFAULT)
    `uvm_field_int(enable_illegal_csr_instruction, UVM_DEFAULT)
    `uvm_field_int(enable_access_invalid_csr_level, UVM_DEFAULT)
    `uvm_field_int(enable_misaligned_instr, UVM_DEFAULT)
    `uvm_field_int(enable_dummy_csr_write, UVM_DEFAULT)
    `uvm_field_int(randomize_csr, UVM_DEFAULT)
    `uvm_field_int(allow_sfence_exception, UVM_DEFAULT)
    `uvm_field_int(no_delegation, UVM_DEFAULT)
    `uvm_field_int(force_m_delegation, UVM_DEFAULT)
    `uvm_field_int(force_s_delegation, UVM_DEFAULT)
    `uvm_field_int(support_supervisor_mode, UVM_DEFAULT)
    `uvm_field_int(disable_compressed_instr, UVM_DEFAULT)
    `uvm_field_int(signature_addr, UVM_DEFAULT)
    `uvm_field_int(num_of_harts, UVM_DEFAULT)
    `uvm_field_int(require_signature_addr, UVM_DEFAULT)
    `uvm_field_int(gen_debug_section, UVM_DEFAULT)
    `uvm_field_int(enable_ebreak_in_debug_rom, UVM_DEFAULT)
    `uvm_field_int(set_dcsr_ebreak, UVM_DEFAULT)
    `uvm_field_int(num_debug_sub_program, UVM_DEFAULT)
    `uvm_field_int(enable_debug_single_step, UVM_DEFAULT)
    `uvm_field_int(single_step_iterations, UVM_DEFAULT)
    `uvm_field_int(set_mstatus_tw, UVM_DEFAULT)
    `uvm_field_int(set_mstatus_mprv, UVM_DEFAULT)
    `uvm_field_int(max_branch_step, UVM_DEFAULT)
    `uvm_field_int(max_directed_instr_stream_seq, UVM_DEFAULT)
    `uvm_field_int(enable_floating_point, UVM_DEFAULT)
    `uvm_field_int(enable_vector_extension, UVM_DEFAULT)
    `uvm_field_int(vector_instr_only, UVM_DEFAULT)
    `uvm_field_int(enable_b_extension, UVM_DEFAULT)
    `uvm_field_array_enum(b_ext_group_t, enable_bitmanip_groups, UVM_DEFAULT)
    `uvm_field_int(enable_zba_extension, UVM_DEFAULT)
    `uvm_field_int(enable_zbb_extension, UVM_DEFAULT)
    `uvm_field_int(enable_zbc_extension, UVM_DEFAULT)
    `uvm_field_int(enable_zbs_extension, UVM_DEFAULT)
    `uvm_field_int(use_push_data_section, UVM_DEFAULT)
  `uvm_object_utils_end

  function new (string name = "");
    string s;
    riscv_instr_group_t march_isa[];
    super.new(name);
    init_delegation();
    inst = uvm_cmdline_processor::get_inst();
    get_int_arg_value("+num_of_tests=", num_of_tests);
    get_int_arg_value("+enable_page_table_exception=", enable_page_table_exception);
    get_bool_arg_value("+enable_interrupt=", enable_interrupt);
    get_bool_arg_value("+enable_nested_interrupt=", enable_nested_interrupt);
    get_bool_arg_value("+enable_timer_irq=", enable_timer_irq);
    get_int_arg_value("+num_of_sub_program=", num_of_sub_program);
    get_int_arg_value("+instr_cnt=", instr_cnt);
    get_bool_arg_value("+no_ebreak=", no_ebreak);
    get_bool_arg_value("+no_ecall=", no_ecall);
    get_bool_arg_value("+no_dret=", no_dret);
    get_bool_arg_value("+no_wfi=", no_wfi);
    get_bool_arg_value("+no_branch_jump=", no_branch_jump);
    get_bool_arg_value("+no_load_store=", no_load_store);
    get_bool_arg_value("+no_csr_instr=", no_csr_instr);
    get_bool_arg_value("+fix_sp=", fix_sp);
    get_bool_arg_value("+use_push_data_section=", use_push_data_section);
    get_bool_arg_value("+enable_illegal_csr_instruction=", enable_illegal_csr_instruction);
    get_bool_arg_value("+enable_access_invalid_csr_level=", enable_access_invalid_csr_level);
    get_bool_arg_value("+enable_misaligned_instr=", enable_misaligned_instr);
    get_bool_arg_value("+enable_dummy_csr_write=", enable_dummy_csr_write);
    get_bool_arg_value("+allow_sfence_exception=", allow_sfence_exception);
    get_bool_arg_value("+no_data_page=", no_data_page);
    get_bool_arg_value("+no_directed_instr=", no_directed_instr);
    get_bool_arg_value("+no_fence=", no_fence);
    get_bool_arg_value("+no_delegation=", no_delegation);
    get_int_arg_value("+illegal_instr_ratio=", illegal_instr_ratio);
    get_int_arg_value("+hint_instr_ratio=", hint_instr_ratio);
    get_bool_arg_value("+gen_all_csrs_by_default=", gen_all_csrs_by_default);
    get_bool_arg_value("+gen_csr_ro_write=", gen_csr_ro_write);
    cmdline_enum_processor #(privileged_reg_t)::get_array_values("+add_csr_write=",
                                                              1'b1, add_csr_write);
    cmdline_enum_processor #(privileged_reg_t)::get_array_values("+remove_csr_write=",
                                                              1'b1, remove_csr_write);
    get_int_arg_value("+num_of_harts=", num_of_harts);
    get_bool_arg_value("+enable_unaligned_load_store=", enable_unaligned_load_store);
    get_bool_arg_value("+force_m_delegation=", force_m_delegation);
    get_bool_arg_value("+force_s_delegation=", force_s_delegation);
    get_bool_arg_value("+require_signature_addr=", require_signature_addr);
    get_bool_arg_value("+disable_compressed_instr=", disable_compressed_instr);
    get_bool_arg_value("+randomize_csr=", randomize_csr);
    if (this.require_signature_addr) begin
      get_hex_arg_value("+signature_addr=", signature_addr);
    end
    if ($value$plusargs("tvec_alignment=%0d", tvec_alignment)) begin
      tvec_alignment.rand_mode(0);
    end
    get_bool_arg_value("+gen_debug_section=", gen_debug_section);
    get_bool_arg_value("+bare_program_mode=", bare_program_mode);
    get_int_arg_value("+num_debug_sub_program=", num_debug_sub_program);
    get_bool_arg_value("+enable_ebreak_in_debug_rom=", enable_ebreak_in_debug_rom);
    get_bool_arg_value("+set_dcsr_ebreak=", set_dcsr_ebreak);
    get_bool_arg_value("+enable_debug_single_step=", enable_debug_single_step);
    get_bool_arg_value("+set_mstatus_tw=", set_mstatus_tw);
    get_bool_arg_value("+set_mstatus_mprv=", set_mstatus_mprv);
    get_bool_arg_value("+enable_floating_point=", enable_floating_point);
    get_bool_arg_value("+enable_vector_extension=", enable_vector_extension);
    get_bool_arg_value("+enable_b_extension=", enable_b_extension);
    get_bool_arg_value("+enable_zba_extension=", enable_zba_extension);
    get_bool_arg_value("+enable_zbb_extension=", enable_zbb_extension);
    get_bool_arg_value("+enable_zbc_extension=", enable_zbc_extension);
    get_bool_arg_value("+enable_zbs_extension=", enable_zbs_extension);
    cmdline_enum_processor #(b_ext_group_t)::get_array_values("+enable_bitmanip_groups=",
                                                              1'b0, enable_bitmanip_groups);
    if(inst.get_arg_value("+boot_mode=", boot_mode_opts)) begin
      `uvm_info(get_full_name(), $sformatf(
                "Got boot mode option - %0s", boot_mode_opts), UVM_LOW)
      case(boot_mode_opts)
        "m" : init_privileged_mode = MACHINE_MODE;
        "s" : init_privileged_mode = SUPERVISOR_MODE;
        "u" : init_privileged_mode = USER_MODE;
        default: `uvm_fatal(get_full_name(),
                  $sformatf("Illegal boot mode option - %0s", boot_mode_opts))
      endcase
      init_privileged_mode.rand_mode(0);
      addr_translaction_rnd_order_c.constraint_mode(0);
    end
    `uvm_info(`gfn, $sformatf("riscv_instr_pkg::supported_privileged_mode = %0d",
                   riscv_instr_pkg::supported_privileged_mode.size()), UVM_LOW)
    void'(inst.get_arg_value("+asm_test_suffix=", asm_test_suffix));
    // Directed march list from the runtime options, ex. RV32I, RV32M etc.
    cmdline_enum_processor #(riscv_instr_group_t)::get_array_values("+march=", 1'b0, march_isa);
    if (march_isa.size != 0) riscv_instr_pkg::supported_isa = march_isa;

    if (!(RV32C inside {supported_isa})) begin
      disable_compressed_instr = 1;
    end

    if (!((RV32ZBA inside {supported_isa}) ||
          (RV64ZBA inside {supported_isa}))) begin
      enable_zba_extension = 0;
    end

    if (!((RV32ZBB inside {supported_isa}) ||
          (RV64ZBB inside {supported_isa}))) begin
      enable_zbb_extension = 0;
    end

    if (!((RV32ZBC inside {supported_isa}) ||
          (RV64ZBC inside {supported_isa}))) begin
      enable_zbc_extension = 0;
    end

    if (!((RV32ZBS inside {supported_isa}) ||
          (RV64ZBS inside {supported_isa}))) begin
      enable_zbs_extension = 0;
    end

    vector_cfg = riscv_vector_cfg::type_id::create("vector_cfg");
    pmp_cfg = riscv_pmp_cfg::type_id::create("pmp_cfg");
    pmp_cfg.rand_mode(pmp_cfg.pmp_randomize);
    pmp_cfg.initialize(signature_addr);
    setup_instr_distribution();
    get_invalid_priv_lvl_csr();
  endfunction

  virtual function void setup_instr_distribution();
    string opts;
    int val;
    get_int_arg_value("+dist_control_mode=", dist_control_mode);
    if (dist_control_mode == 1) begin
      riscv_instr_category_t category;
      category = category.first;
      do begin
        opts = {$sformatf("dist_%0s=", category.name()), "%d"};
        opts = opts.tolower();
        if ($value$plusargs(opts, val)) begin
          category_dist[category] = val;
        end else begin
          category_dist[category] = 10; // Default ratio
        end
        `uvm_info(`gfn, $sformatf("Set dist[%0s] = %0d",
                        category.name(), category_dist[category]), UVM_LOW)
        category = category.next;
      end
      while(category != category.first);
    end
  endfunction

  // Initialize the exception/interrupt delegation associate array, set all delegation default to 0
  virtual function void init_delegation();
    exception_cause_t cause;
    interrupt_cause_t intr_cause;
    cause = cause.first;
    // Init exception delegation array
    do begin
      m_mode_exception_delegation[cause] = 1'b0;
      s_mode_exception_delegation[cause] = 1'b0;
      cause = cause.next;
    end
    while(cause != cause.first);
    // Init interrupt delegation array
    intr_cause = intr_cause.first;
    do begin
      m_mode_interrupt_delegation[intr_cause] = 1'b0;
      s_mode_interrupt_delegation[intr_cause] = 1'b0;
      intr_cause = intr_cause.next;
    end
    while(intr_cause != intr_cause.first);
  endfunction

  function void pre_randomize();
    foreach (riscv_instr_pkg::supported_privileged_mode[i]) begin
      if(riscv_instr_pkg::supported_privileged_mode[i] == SUPERVISOR_MODE)
        support_supervisor_mode = 1;
    end
  endfunction

  virtual function void get_non_reserved_gpr();
  endfunction

  function void post_randomize();
    // Setup the list all reserved registers
    reserved_regs = {tp, sp, scratch_reg};
    // Need to save all loop registers, and RA/T0
    min_stack_len_per_program = 2 * (XLEN/8);
    // Check if the setting is legal
    check_setting();
  endfunction

  virtual function void check_setting();
    bit support_64b;
    bit support_128b;
    foreach (riscv_instr_pkg::supported_isa[i]) begin
      if (riscv_instr_pkg::supported_isa[i] inside {RV64I, RV64M, RV64A, RV64F, RV64D, RV64C,
                                                    RV64B}) begin
        support_64b = 1'b1;
      end else if (riscv_instr_pkg::supported_isa[i] inside {RV128I, RV128C}) begin
        support_128b = 1'b1;
      end
    end
    if (support_128b && XLEN != 128) begin
      `uvm_fatal(`gfn, "XLEN should be set to 128 based on riscv_instr_pkg::supported_isa setting")
    end
    if (!support_128b && support_64b && XLEN != 64) begin
      `uvm_fatal(`gfn, "XLEN should be set to 64 based on riscv_instr_pkg::supported_isa setting")
    end
    if (!(support_128b || support_64b) && XLEN != 32) begin
      `uvm_fatal(`gfn, "XLEN should be set to 32 based on riscv_instr_pkg::supported_isa setting")
    end
    if (!(support_128b || support_64b) && !(SATP_MODE inside {SV32, BARE})) begin
      `uvm_fatal(`gfn, $sformatf("SATP mode %0s is not supported for RV32G ISA", SATP_MODE.name()))
    end
  endfunction

  // Populate invalid_priv_mode_csrs with the main implemented CSRs for each supported privilege
  // mode
  // TODO(udi) - include performance/pmp/trigger CSRs?
  virtual function void get_invalid_priv_lvl_csr();
    string invalid_lvl[$];
    string csr_name;
    privileged_reg_t csr;
    // Debug CSRs are inaccessible from all but Debug Mode, and we cannot boot into Debug Mode
    invalid_lvl.push_back("D");
    case (init_privileged_mode)
      MACHINE_MODE: begin
      end
      SUPERVISOR_MODE: begin
        invalid_lvl.push_back("M");
      end
      USER_MODE: begin
        invalid_lvl.push_back("S");
        invalid_lvl.push_back("M");
      end
      default: begin
        `uvm_fatal(`gfn, "Unsupported initialization privilege mode")
      end
    endcase
    foreach (implemented_csr[i]) begin
      privileged_reg_t csr = implemented_csr[i];
      csr_name = csr.name();
      if (csr_name[0] inside {invalid_lvl}) begin
        invalid_priv_mode_csrs.push_back(implemented_csr[i]);
      end
    end
  endfunction

endclass
