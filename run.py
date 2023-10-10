"""
Copyright 2019 Google LLC

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

     http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.

Regression script for RISC-V random instruction generator
"""

import argparse
import os
import random
import re
import sys
import logging

from scripts.lib import *
from scripts.spike_log_to_trace_csv import *
from scripts.ovpsim_log_to_trace_csv import *
from scripts.whisper_log_trace_csv import *
from scripts.sail_log_to_trace_csv import *
from scripts.instr_trace_compare import *

from types import SimpleNamespace

LOGGER = logging.getLogger()


class SeedGen:    # 生成随机种子
    """An object that will generate a pseudo-random seed for test iterations"""

    def __init__(self, start_seed, fixed_seed, seed_yaml):  
        # start_seed：指定起始种子值，如果提供了这个值，那么每次迭代的种子将是这个值加上迭代次数
        # fixed_seed：指定一个固定的种子值，如果提供了这个值，那么每次迭代的种子都将是这个固定值。这通常用于可重现性。
        # seed_yaml：指定一个YAML文件路径，该文件中包含特定测试ID的种子值。这样，如果需要重新运行某些测试，可以直接使用指定的种子值。
        # These checks are performed with proper error messages at argument
        # parsing time, but it can't hurt to do a belt-and-braces check here too.
        assert fixed_seed is None or start_seed is None        #这两个不能同时生效

        self.fixed_seed = fixed_seed
        self.start_seed = start_seed
        self.rerun_seed = {} if seed_yaml is None else read_yaml(seed_yaml)

    def get(self, test_id, test_iter):
        """Get the seed to use for the given test and iteration"""

        if test_id in self.rerun_seed:  # 首先检查test_id是否在rerun_seed字典中。如果是，那么直接返回对应的种子值。
            # Note that test_id includes the iteration index (well, the batch
            # index, at any rate), so this makes sense even if test_iter > 0.
            return self.rerun_seed[test_id]

        if self.fixed_seed is not None:   # 如果fixed_seed属性不为None，那么说明用户指定了一个固定的种子值。
            # Checked at argument parsing time
            assert test_iter == 0   # 检查，因为只有第一次迭代应该使用固定的种子值
            return self.fixed_seed

        if self.start_seed is not None:
            return self.start_seed + test_iter   # 如果start_seed属性不为None，那么说明用户指定了一个起始种子值。在这种情况下，返回start_seed + test_iter作为种子值

        # If the user didn't specify seeds in some way, we generate a random
        # seed every time
        return random.getrandbits(31)   # 调用get方法时都会生成一个随机的31位种子值


def get_generator_cmd(simulator, simulator_yaml, cov, exp, debug_cmd):   #设置指令生成器的编译和仿真命令
    """ Setup the compile and simulation command for the generator

    Args:
      simulator      : RTL/pyflow simulator used to run instruction generator   # 用于运行指令生成器的RTL/pyflow模拟器
      simulator_yaml : RTL/pyflow simulator configuration file in YAML format   # 以YAML格式指定的RTL/pyflow模拟器配置文件路径
      cov            : Enable functional coverage        # 用于启用功能覆盖率
      exp            : Use experimental version          # 用于使用实验版本
      debug_cmd      : Produce the debug cmd log without running  # 用于生成调试命令日志而不执行

    Returns:
      compile_cmd    : RTL/pyflow simulator command to compile the instruction   # 用于编译指令生成器的RTL/pyflow模拟器命令
                       generator
      sim_cmd        : RTL/pyflow simulator command to run the instruction        # 用于运行指令生成器的RTL/pyflow模拟器命令
                       generator
    """
    logging.info("Processing simulator setup file : {}".format(simulator_yaml))
    yaml_data = read_yaml(simulator_yaml)
    # Search for matched simulator
    for entry in yaml_data:
        if entry['tool'] == simulator:
            logging.info("Found matching simulator: {}".format(entry['tool']))
            if simulator == "pyflow":
                compile_cmd = ""
            else:
                compile_spec = entry['compile']   # 获取编译的spec
                compile_cmd = compile_spec['cmd']  # 获取编译的配置
                for i in range(len(compile_cmd)):
                    if ('cov_opts' in compile_spec) and cov:     #如果有覆盖率的收集，则将<cov_opts> 用cov_opts后的值替换
                        compile_cmd[i] = re.sub('<cov_opts>', compile_spec[
                            'cov_opts'].rstrip(), compile_cmd[i])
                    else:
                        compile_cmd[i] = re.sub('<cov_opts>', '',
                                                compile_cmd[i])
                    if exp:
                        compile_cmd[i] += " +define+EXPERIMENTAL "   # 实验版本的配置
            sim_cmd = entry['sim']['cmd']          #从 entry 的 sim 中 获取 cmd字段
            if ('cov_opts' in entry['sim']) and cov:
                sim_cmd = re.sub('<cov_opts>',
                                 entry['sim']['cov_opts'].rstrip(), sim_cmd)   # 依旧是进行的覆盖率配置替换
            else:
                sim_cmd = re.sub('<cov_opts>', '', sim_cmd)    
            if 'env_var' in entry:
                for env_var in entry['env_var'].split(','):        #用 env_var 替换 env_var的部分
                    for i in range(len(compile_cmd)):
                        compile_cmd[i] = re.sub(
                            "<" + env_var + ">", get_env_var(env_var, debug_cmd=debug_cmd),
                            compile_cmd[i])
                    sim_cmd = re.sub(
                        "<" + env_var + ">", get_env_var(env_var, debug_cmd=debug_cmd),
                        sim_cmd)
            return compile_cmd, sim_cmd
    logging.error("Cannot find simulator {}".format(simulator))
    sys.exit(RET_FAIL)


def parse_iss_yaml(iss, iss_yaml, isa, setting_dir, debug_cmd):    # 解析ISS（Instruction Set Simulator，指令集模拟器）的YAML配置文件，以获取模拟命令
    """Parse ISS YAML to get the simulation command

    Args:
      iss         : target ISS used to look up in ISS YAML     # 模拟器的种类
      iss_yaml    : ISS configuration file in YAML format      # 模拟器配置的路径
      isa         : ISA variant passed to the ISS   # 传递给ISS 的isa指令集
      setting_dir : Generator setting directory   # 生成器设置目录
      debug_cmd   : Produce the debug cmd log without running # 用于生成调试命令日志而不执行

    Returns:
      cmd         : ISS run command   # iss 的运行指令
    """
    logging.info("Processing ISS setup file : {}".format(iss_yaml))
    yaml_data = read_yaml(iss_yaml)   # 读取iss的 文档

    # Path to the "scripts" subdirectory
    my_path = os.path.dirname(os.path.realpath(__file__))
    scripts_dir = os.path.join(my_path, "scripts")   # Search for matched ISS   # 获取当前脚本文件所在的目录的绝对路径，并找到该目录下的"scripts"子目录的绝对路径

    # Search for matched ISS
    for entry in yaml_data:
        if entry['iss'] == iss:
            logging.info("Found matching ISS: {}".format(entry['iss']))
            cmd = entry['cmd'].rstrip()
            cmd = re.sub("\<path_var\>",
                         get_env_var(entry['path_var'], debug_cmd=debug_cmd),   # 通过get_env_var将当前的环境变量传入配置文件
                         cmd)
            m = re.search(r"rv(?P<xlen>[0-9]+?)(?P<variant>[a-zA-Z_]+?)$", isa)  # 搜索RV数字字母的 指令集的文件 在target目录中
            if m:
                cmd = re.sub("\<xlen\>", m.group('xlen'), cmd)    # 把RV之后的数字替换
            else:
                logging.error("Illegal ISA {}".format(isa))   # 没有的话就报错
            if iss == "ovpsim":      
                cmd = re.sub("\<cfg_path\>", setting_dir, cmd)
            elif iss == "whisper":
                if m:
                    # TODO: Support u/s mode
                    variant = re.sub('g', 'imafd', m.group('variant'))
                    cmd = re.sub("\<variant\>", variant, cmd)
            else:
                cmd = re.sub("\<variant\>", isa, cmd)
            cmd = re.sub("\<scripts_path\>", scripts_dir, cmd)
            return cmd
    logging.error("Cannot find ISS {}".format(iss))
    sys.exit(RET_FAIL)


def get_iss_cmd(base_cmd, elf, log):     # 准备 iss 模拟器的cmd 指令
    """Get the ISS simulation command

    Args:
      base_cmd : Original command template
      elf      : ELF file to run ISS simualtion
      log      : ISS simulation log name

    Returns:
      cmd      : Command for ISS simulation
    """
    cmd = re.sub("\<elf\>", elf, base_cmd)   # 将base_cmd 中的 <elf> 替换为传入的 elf
    cmd += (" &> {}".format(log))  形成 base_cmd + log 的 字符串
    return cmd


def do_compile(compile_cmd, test_list, core_setting_dir, cwd, ext_dir,    # 编译随机指令生成器
               cmp_opts, output_dir, debug_cmd, lsf_cmd):
    """Compile the instruction generator

    Args:
      compile_cmd         : Compile command for the generator          编译指令生成器的命令。
      test_list           : List of assembly programs to be compiled   要编译的汇编程序列表。
      core_setting_dir    : Path for riscv_core_setting.sv             riscv_core_setting.sv文件的路径。
      cwd                 : Filesystem path to RISCV-DV repo           RISCV-DV仓库的文件系统路径
      ext_dir             : User extension directory                   用户扩展目录
      cmp_opts            : Compile options for the generator          编译指令生成器的选项
      output_dir          : Output directory of the ELF files          ELF文件的输出目录
      debug_cmd           : Produce the debug cmd log without running  用于在不运行的情况下生成调试命令日志的参数
      lsf_cmd             : LSF command used to run the instruction generator   用于运行指令生成器的LSF命令
    """
    if not ((len(test_list) == 1) and (                                # test_list 的长度不为1 且第一个不是riscv_csr_test
            test_list[0]['test'] == 'riscv_csr_test')):
        logging.info("Building RISC-V instruction generator")          # 构建RISC-V 随机指令发生器
        for cmd in compile_cmd:                      
            cmd = re.sub("<out>", os.path.abspath(output_dir), cmd)    # 输出路径
            cmd = re.sub("<setting>", core_setting_dir, cmd)           # setting 路径   riscv_core_setting.sv 
            if ext_dir == "":
                cmd = re.sub("<user_extension>", "<cwd>/user_extension", cmd)  # 拓展的文件夹
            else:             
                cmd = re.sub("<user_extension>", ext_dir, cmd)
            cmd = re.sub("<cwd>", cwd, cmd)                 # 文件系统路径
            cmd = re.sub("<cmp_opts>", cmp_opts, cmd)       # 编译指令生成器的选项
            if lsf_cmd:
                cmd = lsf_cmd + " " + cmd                   # 加集群的配置
                run_parallel_cmd([cmd], debug_cmd=debug_cmd)  # 多个同时跑
            else:
                logging.debug("Compile command: {}".format(cmd))
                run_cmd(cmd, debug_cmd=debug_cmd)           # 运行随机指令生成器


def run_csr_test(cmd_list, cwd, csr_file, isa, iterations, lsf_cmd,       # control and status reg  测试
                 end_signature_addr, timeout_s, output_dir, debug_cmd):
     #命令列表、当前工作目录、CSR文件路径、ISA（Instruction Set Architecture，指令集架构）字符串、迭代次数、LSF命令、结束签名地址、超时时间和输出目录
    """Run CSR test
     It calls a separate python script to generate directed CSR test code,
     located at scripts/gen_csr_test.py.
    """
    cmd = "python3 " + cwd + "/scripts/gen_csr_test.py" + \
          (" --csr_file {}".format(csr_file)) + \
          (" --xlen {}".format(
              re.search(r"(?P<xlen>[0-9]+)", isa).group("xlen"))) + \
          (" --iterations {}".format(iterations)) + \
          (" --out {}/asm_test".format(output_dir)) + \
          (" --end_signature_addr {}".format(end_signature_addr))
    if lsf_cmd:
        cmd_list.append(cmd)
    else:
        run_cmd(cmd, timeout_s, debug_cmd=debug_cmd)


def do_simulate(sim_cmd, simulator, test_list, cwd, sim_opts, seed_gen,    # 运行指令生成器（instruction generator）并进行仿真
                csr_file,
                isa, end_signature_addr, lsf_cmd, timeout_s, log_suffix,
                batch_size, output_dir, verbose, check_return_code, debug_cmd, target):
    """Run  the instruction generator

    Args:
      sim_cmd               : Simulate command for the generator                 字符串类型的参数，指定了用于运行指令生成器的仿真命令
      simulator             : simulator used to run instruction generator        字符串类型的参数，指定了用于运行指令生成器的仿真器
      test_list             : List of assembly programs to be compiled           列表类型的参数，包含了要编译的汇编程序列表
      cwd                   : Filesystem path to RISCV-DV repo                   字符串类型的参数，指定了RISCV-DV仓库的文件系统路径
      sim_opts              : Simulation options for the generator               字符串类型的参数，指定了用于运行指令生成器的仿真选项
      seed_gen              : A SeedGen seed generator                           种子生成器对象，用于生成随机种子以进行仿真
      csr_file              : YAML file containing description of all CSRs       字符串类型的参数，指定了包含所有CSR描述的YAML文件路径
      isa                   : Processor supported ISA subset                     字符串类型的参数，指定了处理器支持的ISA指令集
      end_signature_addr    : Address that tests will write pass/fail signature to at end of test    整数类型的参数，指定了测试将在结束时将通过/失败的标志写入的地址
      lsf_cmd               : LSF command used to run the instruction generator      字符串类型的参数，指定了用于运行指令生成器的LSF命令
      timeout_s             : Timeout limit in seconds                           整数类型的参数，指定了仿真的超时时间限制（以秒为单位）
      log_suffix            : Simulation log file name suffix                    字符串类型的参数，指定了仿真日志文件名的后缀
      batch_size            : Number of tests to generate per run                整数类型的参数，指定了每次运行生成的测试数量
      output_dir            : Output directory of the ELF files                  字符串类型的参数，指定了ELF文件的输出目录
      verbose               : Verbose logging                                    布尔类型的参数，指定了是否启用详细日志记录
      check_return_code     : Check return code of the command                   布尔类型的参数，指定了是否检查命令的返回码
      debug_cmd             : Produce the debug cmd log without running          布尔类型的参数，指定了是否生成调试命令日志而不执行命令   
    """
    cmd_list = []
    sim_cmd = re.sub("<out>", os.path.abspath(output_dir), sim_cmd)   # os.path.abspath函数用于获取输出目录的绝对路径，确保路径的正确性。
    sim_cmd = re.sub("<cwd>", cwd, sim_cmd)
    sim_cmd = re.sub("<sim_opts>", sim_opts, sim_cmd)

    logging.info("Running RISC-V instruction generator")              # 打印消息 运行 RISCV 指令发生器
    sim_seed = {}
    for test in test_list:                                            # 相当于把test 转化成 cmd
        iterations = test['iterations']                               # 测试的迭代次数
        logging.info("Generating {} {}".format(iterations, test['test']))
        if iterations > 0:
            # Running a CSR test
            if test['test'] == 'riscv_csr_test':
                run_csr_test(cmd_list, cwd, csr_file, isa, iterations, lsf_cmd,   # 控制寄存器测试
                             end_signature_addr, timeout_s, output_dir,
                             debug_cmd)
            else:
                batch_cnt = 1
                if batch_size > 0:
                    batch_cnt = int((iterations + batch_size - 1) / batch_size)    # 计算出运行的次数
                logging.info(
                    "Running {} with {} batches".format(test['test'],
                                                        batch_cnt))
                for i in range(0, batch_cnt):
                    test_id = '{}_{}'.format(test['test'], i)
                    rand_seed = seed_gen.get(test_id, i * batch_cnt)       # 得到随机种子
                    if i < batch_cnt - 1:
                        test_cnt = batch_size
                    else:
                        test_cnt = iterations - i * batch_size              # 运行次数
                    if simulator == "pyflow":                               # 运行的sim_cmd 和 cmd
                        sim_cmd = re.sub("<test_name>", test['gen_test'],
                                         sim_cmd)
                        cmd = lsf_cmd + " " + sim_cmd.rstrip() + \
                              (" --num_of_tests={}".format(test_cnt)) + \
                              (" --start_idx={}".format(i * batch_size)) + \
                              (" --asm_file_name={}/asm_test/{}".format(
                                  output_dir, test['test'])) + \
                              (" --log_file_name={}/sim_{}_{}{}.log ".format(
                                  output_dir,
                                  test['test'], i, log_suffix)) + \
                              (" --target=%s " % (target)) + \
                              (" --gen_test=%s " % (test['gen_test'])) + \
                              (" --seed={} ".format(rand_seed))
                    else:                                                      # 其余的cmd
                        cmd = lsf_cmd + " " + sim_cmd.rstrip() + \
                              (" +UVM_TESTNAME={} ".format(test['gen_test'])) + \
                              (" +num_of_tests={} ".format(test_cnt)) + \
                              (" +start_idx={} ".format(i * batch_size)) + \
                              (" +asm_file_name={}/asm_test/{} ".format(
                                  output_dir, test['test'])) + \
                              (" -l {}/sim_{}_{}{}.log ".format(
                                  output_dir, test['test'], i, log_suffix))
                    if verbose and simulator != "pyflow":                      # 详细的记录
                        cmd += "+UVM_VERBOSITY=UVM_HIGH "
                    cmd = re.sub("<seed>", str(rand_seed), cmd)                # 加入seed
                    cmd = re.sub("<test_id>", test_id, cmd)                    # 加入test_id
                    sim_seed[test_id] = str(rand_seed)                         # 保存种子号
                    if "gen_opts" in test:
                        if simulator == "pyflow":
                            test['gen_opts'] = re.sub("\+", "--",
                                                      test['gen_opts'])        # 将test['gen_opts']字符串中的所有+字符替换为--字符
                            cmd += test['gen_opts']
                        else:
                            cmd += test['gen_opts']
                    if not re.search("c", isa):
                        cmd += "+disable_compressed_instr=1 "                  # 指令集的名字中没有c,则禁用压缩
                    if lsf_cmd:
                        cmd_list.append(cmd)                                   # 如果是lsf，就把cmd加到cmd_list中
                    else:
                        logging.info(
                            "Running {}, batch {}/{}, test_cnt:{}".format(     # 如果不是lsf，则打印 test_name 第几次运行/共几次  运行次数
                                test['test'], i + 1, batch_cnt, test_cnt))
                        run_cmd(cmd, timeout_s,                                # 运行
                                check_return_code=check_return_code,
                                debug_cmd=debug_cmd)
    if sim_seed:
        with open(('{}/seed.yaml'.format(os.path.abspath(output_dir))),        # 打开seed.yaml 没有这个文件的话就创建一个
                  'w') as outfile:                             
            yaml.dump(sim_seed, outfile, default_flow_style=False)             # 把seed种子号保存起来
    if lsf_cmd:                                                                # 如果使用的是lsf 则使用 cmd_list 跑程序
        run_parallel_cmd(cmd_list, timeout_s,
                         check_return_code=check_return_code,
                         debug_cmd=debug_cmd)


def gen(test_list, argv, output_dir, cwd):    #  运行指令发生器 todo： 和上面的有什么区别
    """Run the instruction generator

    Args:
      test_list             : List of assembly programs to be compiled   要编译的汇编程序列表
      argv                  : Configuration arguments                    配置参数
      output_dir            : Output directory of the ELF files          ELF文件的输出目录
      cwd                   : Filesystem path to RISCV-DV repo           RISCV-DV仓库的文件系统路径
    """
    check_return_code = True        # 默认情况下需要检查指令生成器的返回码
    if argv.simulator == "ius":     # 使用的是Incisive模拟器，它将在测试通过时返回非零的返回码。
        # Incisive return non-zero return code even test passes
        check_return_code = False      
        logging.debug(
            "Disable return_code checking for {}".format(argv.simulator))
    # Mutually exclusive options between compile_only and sim_only        
    if argv.co and argv.so:                  # 仅编译 仅模拟 互斥
        logging.error("argument -co is not allowed with argument -so")
        return
    if argv.co == 0 and len(test_list) == 0:    # 没有指定编译选项；test_list列表的长度为0，表示没有需要模拟的测试程序。说明没有需要编译的测试程序，也没有需要模拟的测试程序
        return
    # Setup the compile and simulation command for the generator
    compile_cmd, sim_cmd = get_generator_cmd(argv.simulator,        #设置指令生成器的编译和仿真命令
                                             argv.simulator_yaml, argv.cov,
                                             argv.exp, argv.debug)
    # Compile the instruction generator
    # No compilation process in pyflow simulator      # 编译过程， 在pyflow模拟器中没有编译的过程
    if not argv.so:                   # 如果不是仅仿真，就执行编译
        do_compile(compile_cmd, test_list, argv.core_setting_dir, cwd,
                   argv.user_extension_dir,
                   argv.cmp_opts, output_dir, argv.debug, argv.lsf_cmd)
    # Run the instruction generator
    if not argv.co:                   # 如果不是仅编译，就执行仿真
        seed_gen = SeedGen(argv.start_seed, argv.seed, argv.seed_yaml)
        if argv.simulator == 'pyflow':   # 根据是否是 pyflow 指定仿真时间
            """Default timeout of Pyflow is 20 minutes, if the user
               doesn't specified their own gen_timeout value from CMD
            """
            if argv.gen_timeout == 360:
                gen_timeout = 1200
            else:
                gen_timeout = argv.gen_timeout
        else:
            gen_timeout = argv.gen_timeout
        do_simulate(sim_cmd, argv.simulator, test_list, cwd, argv.sim_opts,    # 开启仿真
                    seed_gen,
                    argv.csr_yaml, argv.isa, argv.end_signature_addr,
                    argv.lsf_cmd,
                    gen_timeout, argv.log_suffix, argv.batch_size,
                    output_dir,
                    argv.verbose, check_return_code, argv.debug, argv.target)


def gcc_compile(test_list, output_dir, isa, mabi, opts, debug_cmd):      # 使用RISC-V GCC工具链编译汇编
    """Use riscv gcc toolchain to compile the assembly program

    Args:
      test_list  : List of assembly programs to be compiled       包含要编译的汇编程序的列表
      output_dir : Output directory of the ELF files              字符串，表示ELF文件的输出目录
      isa        : ISA variant passed to GCC                      字符串，表示传递给GCC的ISA变体，例如RV32I是32位整数指令集，RV64I是64位整数指令集，RV128I是128位整数指令集。
      mabi       : MABI variant passed to GCC                     字符串，表示传递给GCC的MABI变体，MABI定义了整数和浮点调用约定，例如ILP32 MABI在32位系统中使用32位整数和32位浮点数，LP64 MABI在64位系统中使用64位整数和64位浮点数
      debug_cmd  : Produce the debug cmd log without running      布尔类型的变量，用于指示是否生成调试命令日志而不执行命令。
    """
    cwd = os.path.dirname(os.path.realpath(__file__))
    for test in test_list:
        for i in range(0, test['iterations']):
            if 'no_gcc' in test and test['no_gcc'] == 1:           判断是否不需要 gcc编译
                continue
            prefix = ("{}/asm_test/{}_{}".format(output_dir, test['test'], i))
            asm = prefix + ".S"              # 生成汇编文件的路径和名称
            elf = prefix + ".o"              # 生成ELF文件的路径和名称
            binary = prefix + ".bin"         # 生成二进制文件的路径和名称
            test_isa = isa
            if not os.path.isfile(asm) and not debug_cmd:    # 检查汇编文件是否存在，不存在的话就报错
                logging.error("Cannot find assembly test: {}\n".format(asm))
                sys.exit(RET_FAIL)
            # gcc compilation                      # 生成 gcc的指令
            cmd = ("{} -static -mcmodel=medany \
             -fvisibility=hidden -nostdlib \
             -nostartfiles {} \
             -I{}/user_extension \
             -T{}/scripts/link.ld {} -o {} ".format(
                get_env_var("RISCV_GCC", debug_cmd=debug_cmd), asm, cwd,
                cwd, opts, elf))
            if 'gcc_opts' in test:              
                cmd += test['gcc_opts']
            if 'gen_opts' in test:
                # Disable compressed instruction       # 禁用压缩指令
                if re.search('disable_compressed_instr', test['gen_opts']):
                    test_isa = re.sub("c", "", test_isa)
            # If march/mabi is not defined in the test gcc_opts, use the default
            # setting from the command line.
            if not re.search('march', cmd):
                cmd += (" -march={}".format(test_isa))     # 处理器的架构
            if not re.search('mabi', cmd):
                cmd += (" -mabi={}".format(mabi))          # 处理器mabi变种
            logging.info("Compiling {}".format(asm))       # 编译汇编文件
            run_cmd_output(cmd.split(), debug_cmd=debug_cmd)  # 在Python中执行Shell命令并返回命令输出
            # Convert the ELF to plain binary, used in RTL sim
            logging.info("Converting to {}".format(binary))  # 转化成二进制文件
            cmd = ("{} -O binary {} {}".format(
                get_env_var("RISCV_OBJCOPY", debug_cmd=debug_cmd), elf, binary))  # RISCV_OBJCOPY工具： 将ELF 格式的对象文件转换为二进制格式或者其他格式的文件
            run_cmd_output(cmd.split(), debug_cmd=debug_cmd)   # 在Python中执行Shell命令并返回命令输出  
                  # "riscv64-unknown-elf-gcc -o test test.c"，那么 cmd.split() 的结果就是 ["riscv64-unknown-elf-gcc", "-o", "test", "test.c"]


def run_assembly(asm_test, iss_yaml, isa, mabi, gcc_opts, iss_opts, output_dir,
                 setting_dir, debug_cmd):           # 使用iss 模拟器进行定向汇编测试
    """Run a directed assembly test with ISS

    Args:
      asm_test    : Assembly test file                           汇编测试文件 
      iss_yaml    : ISS configuration file in YAML format        YAML 格式的 ISS 配置文件
      isa         : ISA variant passed to the ISS                传递给 ISS 的 ISA 变体
      mabi        : MABI variant passed to GCC                   传给 GCC 的 MABI 变体
      gcc_opts    : User-defined options for GCC compilation     用于 GCC 编译的用户自定义选项
      iss_opts    : Instruction set simulators                   指令集模拟器
      output_dir  : Output directory of compiled test files      编译测试文件的输出目录
      setting_dir : Generator setting directory                  生成器设置目录
      debug_cmd   : Produce the debug cmd log without running    在不运行的情况下生成调试 cmd 日志
    """
    if not asm_test.endswith(".S"):                             # 检查文件是否以.S 结尾，汇编文件均以.S 结尾
        logging.error("{} is not an assembly .S file".format(asm_test))
        return
    cwd = os.path.dirname(os.path.realpath(__file__))          # 获取当前执行脚本所在的目录路径
    asm_test = os.path.expanduser(asm_test)                    # 来解析用户主目录的缩写（如 "~"），并将其扩展为完整的用户主目录路径，
    report = ("{}/iss_regr.log".format(output_dir)).rstrip()   # 生成一个报告文件的路径和名称,rstrip()方法去除路径字符串末尾的空格和换行符
    asm = re.sub(r"^.*\/", "", asm_test)                       # 只保留 asm中的文件名部分
    asm = re.sub(r"\.S$", "", asm)                             # 把.S 删了只剩名字
    prefix = ("{}/directed_asm_test/{}".format(output_dir, asm))  # 文件的路径
    elf = prefix + ".o"            # elf文件的路径
    binary = prefix + ".bin"       # binary 文件的路径
    iss_list = iss_opts.split(",")    # 分隔iss_opt选项                   
    run_cmd("mkdir -p {}/directed_asm_test".format(output_dir))    # 创建输出路径的文件夹
    logging.info("Compiling assembly test : {}".format(asm_test))   # 编译测试文件

    # gcc compilation
    cmd = ("{} -static -mcmodel=medany \             # 使用RISC-V GCC 编译器来编译汇编测试文件
         -fvisibility=hidden -nostdlib \
         -nostartfiles {} \
         -I{}/user_extension \
         -T{}/scripts/link.ld {} -o {} ".format(
        get_env_var("RISCV_GCC", debug_cmd=debug_cmd), asm_test, cwd,     # 这个环境变量存储了 RISC-V GCC 编译器的路径
        cwd, gcc_opts, elf))
    cmd += (" -march={}".format(isa))    # 两行代码是将 ISA 和 MABI 的值添加到编译命令中。
    cmd += (" -mabi={}".format(mabi))
    run_cmd_output(cmd.split(), debug_cmd=debug_cmd)    # 执行这个cmd shell执行
    # Convert the ELF to plain binary, used in RTL sim   # 用来将编译生成的 ELF 文件转换为纯二进制文件
    logging.info("Converting to {}".format(binary))
    cmd = ("{} -O binary {} {}".format(
        get_env_var("RISCV_OBJCOPY", debug_cmd=debug_cmd), elf, binary))   # 这个环境变量存储了 RISC-V objcopy 工具的路径
    run_cmd_output(cmd.split(), debug_cmd=debug_cmd)    # 执行这个cmd shell执行
    log_list = []   # 空列表，用于存储日志文件的路径和名称
    # ISS simulation
    for iss in iss_list:       # 是一个由 ISS 选项组成的列表，每个元素代表一个不同的 ISS。
        run_cmd("mkdir -p {}/{}_sim".format(output_dir, iss))   # 创建一个用于存储 ISS 仿真结果的目录。目录的路径由 output_dir 和 iss 变量组成。
        log = ("{}/{}_sim/{}.log".format(output_dir, iss, asm))  # 生成一个日志文件的路径和名称，该日志文件用于记录 ISS 仿真的结果
        log_list.append(log)   # 这行代码是将生成的日志文件路径和名称添加到 log_list 列表中，以便后续使用
        base_cmd = (iss, iss_yaml, isa, setting_dir, debug_cmd)   # 解析ISS（Instruction Set Simulator，指令集模拟器）的YAML配置文件，以获取模拟命令
        logging.info("[{}] Running ISS simulation: {}".format(iss, elf))  # 跑 ISS 模拟器
        cmd = get_iss_cmd(base_cmd, elf, log)   # 准备 iss 模拟器的 cmd指令
        run_cmd(cmd, 10, debug_cmd=debug_cmd)   # 跑iss 模拟器 并且把结果存在log文件里
        logging.info("[{}] Running ISS simulation: {} ...done".format(iss, elf))
    if len(iss_list) == 2:   # 比较两个不同 ISS 的仿真结果。该函数的参数包括 ISS 选项的列表、日志文件路径和名称的列表以及报告文件的路径和名称
        compare_iss_log(iss_list, log_list, report) 


def run_assembly_from_dir(asm_test_dir, iss_yaml, isa, mabi, gcc_opts, iss,  # 和上面的函数差不多，只不过这个是从一个目录里面遍历所有的汇编测试文件
                          output_dir, setting_dir, debug_cmd):
    """Run a directed assembly test from a directory with spike

    Args:
      asm_test_dir    : Assembly test file directory
      iss_yaml        : ISS configuration file in YAML format
      isa             : ISA variant passed to the ISS
      mabi            : MABI variant passed to GCC
      gcc_opts        : User-defined options for GCC compilation
      iss             : Instruction set simulators
      output_dir      : Output directory of compiled test files
      setting_dir     : Generator setting directory
      debug_cmd       : Produce the debug cmd log without running
     1.遍历指定目录中的所有汇编测试文件。
     2.对每个汇编测试文件，使用GCC编译器和指定的编译选项进行编译，生成ELF（Executable and Linkable Format，可执行与可链接格式）文件。
     3.将ELF文件转换为纯二进制文件，以便在RTL（Register-Transfer Level，寄存器传输级别）仿真中使用。
     4.使用指定的ISS模拟器对二进制文件进行仿真。
     5.记录仿真结果和其他相关信息，如使用的ISS、ISA、MABI等。
     6.如果指定了多个ISS模拟器，还可以比较不同模拟器的仿真结果。
    """
    result = run_cmd("find {} -name \"*.S\"".format(asm_test_dir))    #搜索指定目录中所有以 .S 结尾的文件。
    if result:
        asm_list = result.splitlines()
        logging.info("Found {} assembly tests under {}".format(
            len(asm_list), asm_test_dir))
        for asm_file in asm_list:
            run_assembly(asm_file, iss_yaml, isa, mabi, gcc_opts, iss,   # 运行上一个函数
                         output_dir,
                         setting_dir, debug_cmd)
            if "," in iss:
                report = ("{}/iss_regr.log".format(output_dir)).rstrip()
                save_regr_report(report)
    else:
        logging.error(
            "No assembly test(*.S) found under {}".format(asm_test_dir))


def run_c(c_test, iss_yaml, isa, mabi, gcc_opts, iss_opts, output_dir,   # # 使用iss 模拟器进行定向C测试
          setting_dir, debug_cmd):
    """Run a directed c test with ISS 

    Args:
      c_test      : C test file    和上面的类似
      iss_yaml    : ISS configuration file in YAML format
      isa         : ISA variant passed to the ISS
      mabi        : MABI variant passed to GCC
      gcc_opts    : User-defined options for GCC compilation
      iss_opts    : Instruction set simulators
      output_dir  : Output directory of compiled test files
      setting_dir : Generator setting directory
      debug_cmd   : Produce the debug cmd log without running
    """
    if not c_test.endswith(".c"):
        logging.error("{} is not a .c file".format(c_test))    # 如果没有找到.c 结尾的文件，就报错
        return
    cwd = os.path.dirname(os.path.realpath(__file__))
    c_test = os.path.expanduser(c_test)
    report = ("{}/iss_regr.log".format(output_dir)).rstrip()
    c = re.sub(r"^.*\/", "", c_test)
    c = re.sub(r"\.c$", "", c)
    prefix = ("{}/directed_c_test/{}".format(output_dir, c))
    elf = prefix + ".o"
    binary = prefix + ".bin"
    iss_list = iss_opts.split(",")
    run_cmd("mkdir -p {}/directed_c_test".format(output_dir))
    logging.info("Compiling c test : {}".format(c_test))

    # gcc compilation
    cmd = ("{} -mcmodel=medany -nostdlib \
         -nostartfiles {} \
         -I{}/user_extension \
         -T{}/scripts/link.ld {} -o {} ".format(
        get_env_var("RISCV_GCC", debug_cmd=debug_cmd), c_test, cwd,
        cwd, gcc_opts, elf))
    cmd += (" -march={}".format(isa))
    cmd += (" -mabi={}".format(mabi))
    run_cmd_output(cmd.split(), debug_cmd=debug_cmd)
    # Convert the ELF to plain binary, used in RTL sim
    logging.info("Converting to {}".format(binary))
    cmd = ("{} -O binary {} {}".format(
        get_env_var("RISCV_OBJCOPY", debug_cmd=debug_cmd), elf, binary))
    run_cmd_output(cmd.split(), debug_cmd=debug_cmd)
    log_list = []
    # ISS simulation
    for iss in iss_list:
        run_cmd("mkdir -p {}/{}_sim".format(output_dir, iss))
        log = ("{}/{}_sim/{}.log".format(output_dir, iss, c))
        log_list.append(log)
        base_cmd = (iss, iss_yaml, isa, setting_dir, debug_cmd)
        logging.info("[{}] Running ISS simulation: {}".format(iss, elf))
        cmd = get_iss_cmd(base_cmd, elf, log)
        run_cmd(cmd, 10, debug_cmd=debug_cmd)
        logging.info("[{}] Running ISS simulation: {} ...done".format(iss, elf))
    if len(iss_list) == 2:
        compare_iss_log(iss_list, log_list, report)


def run_c_from_dir(c_test_dir, iss_yaml, isa, mabi, gcc_opts, iss,     # 和上面的类似
                   output_dir, setting_dir, debug_cmd):
    """Run a directed c test from a directory with spike

    Args:
      c_test_dir      : C test file directory
      iss_yaml        : ISS configuration file in YAML format
      isa             : ISA variant passed to the ISS
      mabi            : MABI variant passed to GCC
      gcc_opts        : User-defined options for GCC compilation
      iss             : Instruction set simulators
      output_dir      : Output directory of compiled test files
      setting_dir     : Generator setting directory
      debug_cmd       : Produce the debug cmd log without running
    """
    result = run_cmd("find {} -name \"*.c\"".format(c_test_dir))
    if result:
        c_list = result.splitlines()
        logging.info("Found {} c tests under {}".format(len(c_list), c_test_dir))
        for c_file in c_list:
            run_c(c_file, iss_yaml, isa, mabi, gcc_opts, iss, output_dir,
                  setting_dir, debug_cmd)
            if "," in iss:
                report = ("{}/iss_regr.log".format(output_dir)).rstrip()
                save_regr_report(report)
    else:
        logging.error("No c test(*.c) found under {}".format(c_test_dir))


def iss_sim(test_list, output_dir, iss_list, iss_yaml, iss_opts,      # 使用生成的测试程序运行 ISS 仿真
            isa, setting_dir, timeout_s, debug_cmd):
    """Run ISS simulation with the generated test program   

    Args:
      test_list   : List of assembly programs to be compiled
      output_dir  : Output directory of the ELF files
      iss_list    : List of instruction set simulators
      iss_yaml    : ISS configuration file in YAML format
      iss_opts    : ISS command line options
      isa         : ISA variant passed to the ISS
      setting_dir : Generator setting directory
      timeout_s   : Timeout limit in seconds
      debug_cmd   : Produce the debug cmd log without running
    """
    for iss in iss_list.split(","):
        log_dir = ("{}/{}_sim".format(output_dir, iss))
        base_cmd = parse_iss_yaml(iss, iss_yaml, isa, setting_dir, debug_cmd)  # 解析ISS（Instruction Set Simulator，指令集模拟器）的YAML配置文件，以获取模拟命令
        logging.info("{} sim log dir: {}".format(iss, log_dir))
        run_cmd_output(["mkdir", "-p", log_dir])
        for test in test_list:
            if 'no_iss' in test and test['no_iss'] == 1:
                continue
            else:
                for i in range(0, test['iterations']):
                    prefix = ("{}/asm_test/{}_{}".format(
                        output_dir, test['test'], i))
                    elf = prefix + ".o"
                    log = ("{}/{}_{}.log".format(log_dir, test['test'], i))
                    cmd = get_iss_cmd(base_cmd, elf, log)    # # 准备 iss 模拟器的cmd 指令
                    if 'iss_opts' in test:
                        cmd += ' '
                        cmd += test['iss_opts']
                    logging.info("Running {} sim: {}".format(iss, elf))
                    if iss == "ovpsim":
                        run_cmd(cmd, timeout_s, debug_cmd=debug_cmd)
                    else:
                        run_cmd(cmd, timeout_s, debug_cmd=debug_cmd)
                    logging.debug(cmd)


def iss_cmp(test_list, iss, output_dir, stop_on_first_error, exp, debug_cmd):    # 比较 ISS 模拟结果
    """Compare ISS simulation reult

    Args:
      test_list      : List of assembly programs to be compiled     要编译的汇编程序列表
      iss            : List of instruction set simulators           指令集模拟器列表
      output_dir     : Output directory of the ELF files            ELF文件的输出目录
      stop_on_first_error : will end run on first error detected    是否检测到第一个错误时停止运行
      exp            : Use experimental version                     使用实验版本的模拟器进行比较
      debug_cmd      : Produce the debug cmd log without running    生成调试命令日志但不执行命令
      遍历汇编程序列表和模拟器列表，对每个汇编程序使用指定的模拟器进行模拟执行。比较不同模拟器的模拟结果，检查是否存在差异或错误。
    """
    if debug_cmd:
        return
    iss_list = iss.split(",")
    if len(iss_list) != 2:
        return
    report = ("{}/iss_regr.log".format(output_dir)).rstrip()         # 输出的 report 地址
    run_cmd("rm -rf {}".format(report))                              # 清空原来的文件夹内容
    for test in test_list:
        for i in range(0, test['iterations']):                       # 跑的次数
            elf = ("{}/asm_test/{}_{}.o".format(output_dir, test['test'], i))      # 汇编程序的测试
            logging.info("Comparing ISS sim result {}/{} : {}".format(
                iss_list[0], iss_list[1], elf))
            log_list = []
            run_cmd(("echo 'Test binary: {}' >> {}".format(elf, report)))    # 把elf字符串 追加保存在reprot中
            for iss in iss_list:
                log_list.append(
                    "{}/{}_sim/{}.{}.log".format(output_dir, iss, test['test'], i))
            compare_iss_log(iss_list, log_list, report, stop_on_first_error,      # 比对
                            exp)
    save_regr_report(report)     # 保存比对结果


def compare_iss_log(iss_list, log_list, report, stop_on_first_error=0,          #比较两个指令集模拟器（ISS）的日志输出
                    exp=False):
    if len(iss_list) != 2 or len(log_list) != 2:                       # 函数检查iss_list和log_list的长度是否都为2
        logging.error("Only support comparing two ISS logs")
    else:
        csv_list = []           # 创建一个空的csv_list列表，用于存储转换后的CSV文件
        for i in range(2):      
            log = log_list[i]
            csv = log.replace(".log", ".csv")
            iss = iss_list[i]
            csv_list.append(csv)
            if iss == "spike":
                process_spike_sim_log(log, csv)       # 处理spike模拟日志文件，提取指令和受影响的寄存器信息，并将结果写入CSV文件， 下同
            elif iss == "ovpsim":
                process_ovpsim_sim_log(log, csv, stop_on_first_error)
            elif iss == "sail":
                process_sail_sim_log(log, csv)
            elif iss == "whisper":
                process_whisper_sim_log(log, csv)
            else:
                logging.error("Unsupported ISS {}".format(iss))
                sys.exit(RET_FAIL)
        result = compare_trace_csv(csv_list[0], csv_list[1], iss_list[0],  # 比较两个 CSV 文件，scripts/instr_trace_compare.py
                                   iss_list[1], report)
        logging.info(result)


def save_regr_report(report):     # 统计report中的 pass和fail数量 并 输出到 report中
    passed_cnt = run_cmd("grep PASSED {} | wc -l".format(report)).strip()
    failed_cnt = run_cmd("grep FAILED {} | wc -l".format(report)).strip()
    summary = ("{} PASSED, {} FAILED".format(passed_cnt, failed_cnt))
    logging.info(summary)
    run_cmd(("echo {} >> {}".format(summary, report)))
    logging.info("ISS regression report is saved to {}".format(report))


def read_seed(arg):   # 从命令行中解析 seed 种子号
    """Read --seed or --seed_start"""
    try:
        seed = int(arg)
        if seed < 0: # seed < 0 报错 
            raise ValueError('bad seed')
        return seed

    except ValueError:         # 无法转换为整数，报错
        raise argparse.ArgumentTypeError('Bad seed ({}): '
                                         'must be a non-negative integer.'
                                         .format(arg))


def parse_args(cwd):          # 创建一个命令行参数解析器，并返回解析后的参数值
    """Create a command line parser.

    Returns: The created parser.
    """
    # Parse input arguments
    parser = argparse.ArgumentParser()    # Python 标准库 argparse 中的一个类，用于创建命令行参数解析器对象

    parser.add_argument("--target", type=str, default="rv32imc",
                        help="Run the generator with pre-defined targets: \     #  --target 使用预定义的目标运行生成器
                            rv32imc, rv32i, rv32imafdc, rv64imc, rv64gc, \
                            rv64imafdc")
    parser.add_argument("-o", "--output", type=str,
                        help="Output directory name", dest="o")       # --output 输出目录
    parser.add_argument("-tl", "--testlist", type=str, default="",    # --testlist 回归的测试目录
                        help="Regression testlist", dest="testlist")
    parser.add_argument("-tn", "--test", type=str, default="all",     # --test testlist 中的 test 或者all
                        help="Test name, 'all' means all tests in the list",
                        dest="test")
    parser.add_argument("-i", "--iterations", type=int, default=0,    # --iterations 迭代的次数
                        help="Override the iteration count in the test list",
                        dest="iterations")
    parser.add_argument("-si", "--simulator", type=str, default="vcs", # --simulator 选择的模拟器 默认VCS
                        help="Simulator used to run the generator, default VCS",
                        dest="simulator")
    parser.add_argument("--iss", type=str, default="spike",    # --iss 选择的 指令集模拟器
                        help="RISC-V instruction set simulator: spike,ovpsim,sail")
    parser.add_argument("-v", "--verbose", dest="verbose", action="store_true",    # --verbose  详细的log信息 
                        default=False,
                        help="Verbose logging")
    parser.add_argument("--co", dest="co", action="store_true", default=False,    # --co 仅编译    args.co来获取参数
                        help="Compile the generator only")
    parser.add_argument("--cov", dest="cov", action="store_true", default=False,  # --cov  收集覆盖率
                        help="Enable functional coverage")
    parser.add_argument("--so", dest="so", action="store_true", default=False,   # --so  仅仿真
                        help="Simulate the generator only")
    parser.add_argument("--cmp_opts", type=str, default="",       # --cmp_opts 编译选项
                        help="Compile options for the generator")
    parser.add_argument("--sim_opts", type=str, default="",       # --sim_opts 仿真选项
                        help="Simulation options for the generator")
    parser.add_argument("--gcc_opts", type=str, default="",       # -- GCC工具链 选项 汇编 -> 二进制
                        help="GCC compile options")
    parser.add_argument("-s", "--steps", type=str, default="all",  
                        help="Run steps: gen,gcc_compile,iss_sim,iss_cmp",
                        dest="steps")
                         # gen：生成步骤，可能是用于生成RISC-V汇编代码或测试列表的步骤。
                         # gcc_compile：使用GCC编译器编译生成的代码。这个步骤将汇编代码转换为可执行的二进制文件。
                         # iss_sim：ISS模拟器步骤，使用RISC-V指令集模拟器（ISS）来模拟执行编译后的二进制文件。这个步骤将模拟程序在RISC-V处理器上的行为。
                         # iss_cmp：ISS比较步骤，可能是用于比较模拟器的输出和预期结果的步骤。这个步骤可以用于验证模拟器的正确性和准确性。
    parser.add_argument("--lsf_cmd", type=str, default="",                # --lsf_cmd 使用集群
                        help="LSF command. Run in local sequentially if lsf \
                            command is not specified")
    parser.add_argument("--isa", type=str, default="",                # --isa 指令集的子集
                        help="RISC-V ISA subset")
    parser.add_argument("-m", "--mabi", type=str, default="",    # --mabi 指令集的mabi
                        help="mabi used for compilation", dest="mabi")
    parser.add_argument("--gen_timeout", type=int, default=360,      # --gen_timeout timeout
                        help="Generator timeout limit in seconds")
    parser.add_argument("--end_signature_addr", type=str, default="0",    # --end_signature_addr  当测试结束时，程序会将一个特殊的值写入到一个特定的地址，也就是end_signature_addr，以表示测试已经完成
                        help="Address that privileged CSR test writes to at EOT")  #  在EOT End of Test 时写入特权CSR测试的地址（程序可能会写入一些特定的值到某些地址）
    parser.add_argument("--iss_opts", type=str, default="",    # 指令集模拟器的选项
                        help="Any ISS command line arguments")
    parser.add_argument("--iss_timeout", type=int, default=10,  # 指令集模拟器的timeout
                        help="ISS sim timeout limit in seconds")
    parser.add_argument("--iss_yaml", type=str, default="",        # 指令集模拟器的配置文件
                        help="ISS setting YAML")
    parser.add_argument("--simulator_yaml", type=str, default="",
                        help="RTL/pyflow simulator setting YAML")    # RTL 和 pyflow 模拟器的配置文件
    parser.add_argument("--csr_yaml", type=str, default="",          # CSR 的描述文件
                        help="CSR description file")
    parser.add_argument("-ct", "--custom_target", type=str, default="",
                        help="Directory name of the custom target")   # 自定义的目标文件名
    parser.add_argument("-cs", "--core_setting_dir", type=str, default="",
                        help="Path for the riscv_core_setting.sv")    #  riscv_core_setting.sv 的地址
    parser.add_argument("-ext", "--user_extension_dir", type=str, default="",
                        help="Path for the user extension directory")  # 用户自己定义的额外文件夹
    parser.add_argument("--asm_test", type=str, default="",   # 针对性的汇编测试
                        help="Directed assembly tests")
    parser.add_argument("--c_test", type=str, default="",     # 针对性的C测试
                        help="Directed c tests")
    parser.add_argument("--log_suffix", type=str, default="",  # 日志文件的后缀名
                        help="Simulation log name suffix")
    parser.add_argument("--exp", action="store_true", default=False,   # 用实验的模拟器进行
                        help="Run generator with experimental features")
    parser.add_argument("-bz", "--batch_size", type=int, default=0,
                        help="Number of tests to generate per run. You can split a big"    # 每次运行时要生成的测试数量， 将大的任务分小
                             " job to small batches with this option")
    parser.add_argument("--stop_on_first_error", dest="stop_on_first_error",    # 出现第一个错误的时候是否停下
                        action="store_true", default=False,
                        help="Stop on detecting first error")
    parser.add_argument("--noclean", action="store_true", default=True,       # 是否删之前的内容
                        help="Do not clean the output of the previous runs")
    parser.add_argument("--verilog_style_check", action="store_true",             # 启动verilog_style 的检查
                        default=False,
                        help="Run verilog style check")
    parser.add_argument("-d", "--debug", type=str, default="",           # 在log文件中生成debug信息
                        help="Generate debug command log file")

    rsg = parser.add_argument_group('Random seeds',                  # 种子号
                                    'To control random seeds, use at most one '
                                    'of the --start_seed, --seed or --seed_yaml '
                                    'arguments. Since the latter two only give '
                                    'a single seed for each test, they imply '
                                    '--iterations=1.')

    rsg.add_argument("--start_seed", type=read_seed,                # 种子
                     help=("Randomization seed to use for first iteration of "
                           "each test. Subsequent iterations use seeds "
                           "counting up from there. Cannot be used with "
                           "--seed or --seed_yaml."))
    rsg.add_argument("--seed", type=read_seed,              # 种子
                     help=("Randomization seed to use for each test. "
                           "Implies --iterations=1. Cannot be used with "
                           "--start_seed or --seed_yaml."))
    rsg.add_argument("--seed_yaml", type=str,               # 种子
                     help=("Rerun the generator with the seed specification "
                           "from a prior regression. Implies --iterations=1. "
                           "Cannot be used with --start_seed or --seed."))

    args = parser.parse_args()

    if args.seed is not None and args.start_seed is not None:    # 检测是否重复写了 seed 和 start_seed
        logging.error('--start_seed and --seed are mutually exclusive.')
        sys.exit(RET_FAIL)

    if args.seed is not None:
        if args.iterations == 0:       # 在指定了--seed选项的情况下，每次测试只会使用一个固定的随机种子，因此将迭代次数设置为1是合理的
            args.iterations = 1
        elif args.iterations > 1:      # --seed选项和--iterations大于1的设置是互斥的，--seed选项的情况下，每次测试将使用一个固定的随机种子，而--iterations大于1意味着要进行多次测试
            logging.error('--seed is incompatible with setting --iterations '
                          'greater than 1.')
            sys.exit(RET_FAIL)

    # We've parsed all the arguments from the command line; default values
    # can be set in the config file. Read that here.
    load_config(args, cwd)           # load 上述的config

    return args


def load_config(args, cwd):    # 从命令行和配置文件中加载配置 
     # 首先，函数会检查命令行参数args，提取出其中的配置信息。这些信息可能包括要运行的测试类型、测试参数、输出目录等。  
     # 然后，函数会检查当前工作目录下是否存在配置文件。如果存在，函数会读取配置文件，并提取出其中的配置信息。这些信息可能与命令行参数中的配置信息相互补充或覆盖。
     # 最后，函数会将命令行参数和配置文件中的配置信息进行合并和验证，生成一个完整的配置字典，并返回给调用者。
    """
  Load configuration from the command line and the configuration file.
  Args:
      args:   Parsed command-line configuration
  Returns:
      Loaded configuration dictionary.
  """
    if args.debug:    # 如果有 --debug 则 打开一个文件并 把debug内容写在里面
        args.debug = open(args.debug, "w")
    if not args.csr_yaml:
        args.csr_yaml = cwd + "/yaml/csr_template.yaml"    # csr的配置信息文件

    if not args.iss_yaml:     # iss的配置信息文件
        args.iss_yaml = cwd + "/yaml/iss.yaml"

    if not args.simulator_yaml:  # VCS这样的 模拟器的配置信息文件
        args.simulator_yaml = cwd + "/yaml/simulator.yaml"

    # Keep the core_setting_dir option to be backward compatible, suggest to use
    # --custom_target
    if args.core_setting_dir:      # 说明用户没有指定自定义目标的路径，这时程序会根据其他参数来动态地确定测试列表的路径和核心设置目录的路径
        if not args.custom_target:
            args.custom_target = args.core_setting_dir
    else:
        args.core_setting_dir = args.custom_target

    if not args.custom_target:
        if not args.testlist:  # 程序会默认使用当前工作目录下的"target"目录中的对应目标子目录下的"testlist.yaml"文件作为测试列表
            args.testlist = cwd + "/target/" + args.target + "/testlist.yaml"
        if args.simulator == "pyflow":
            args.core_setting_dir = cwd + "/pygen/pygen_src/target/" + args.target
        else:
            args.core_setting_dir = cwd + "/target/" + args.target
        if args.target == "rv32imc":
            args.mabi = "ilp32"
            args.isa = "rv32imc"
        elif args.target == "rv32imafdc":
            args.mabi = "ilp32"
            args.isa = "rv32imafdc"
        elif args.target == "rv32imc_sv32":
            args.mabi = "ilp32"
            args.isa = "rv32imc"
        elif args.target == "multi_harts":
            args.mabi = "ilp32"
            args.isa = "rv32gc"
        elif args.target == "rv32imcb":
            args.mabi = "ilp32"
            args.isa = "rv32imcb"
        elif args.target == "rv32i":
            args.mabi = "ilp32"
            args.isa = "rv32i"
        elif args.target == "rv64imc":
            args.mabi = "lp64"
            args.isa = "rv64imc"
        elif args.target == "rv64imcb":
            args.mabi = "lp64"
            args.isa = "rv64imcb"
        elif args.target == "rv64gc":
            args.mabi = "lp64"
            args.isa = "rv64gc"
        elif args.target == "rv64gcv":
            args.mabi = "lp64"
            args.isa = "rv64gcv"
        elif args.target == "ml":
            args.mabi = "lp64"
            args.isa = "rv64imc"
        elif args.target == "rv64imafdc":
            args.mabi = "lp64"
            args.isa = "rv64imafdc"
        else:
            sys.exit("Unsupported pre-defined target: {}".format(args.target))
    else:
        if re.match(".*gcc_compile.*", args.steps) or re.match(".*iss_sim.*",    # 测试步骤中包含了编译或模拟器执行的步骤
                                                               args.steps):
            if (not args.mabi) or (not args.isa):            # 其中一个为空，说明用户没有指定自定义目标的MABI（Machine ABI）或ISA（Instruction Set Architecture），这时程序会打印一条错误信息并退出
                sys.exit(
                    "mabi and isa must be specified for custom target {}".format(
                        args.custom_target))
        if not args.testlist:      # 如果没有指定测试列表的路径，程序会默认使用自定义目标目录下的"testlist.yaml"文件作为测试列表。
            args.testlist = args.custom_target + "/testlist.yaml"


def main():
    """This is the main entry point."""
    try:
        cwd = os.path.dirname(os.path.realpath(__file__))
        os.environ["RISCV_DV_ROOT"] = cwd    #其他地方可以通过os.environ.get("RISCV_DV_ROOT")来获取当前工作目录的路径

        args = parse_args(cwd)         # 获取 命令行的-- 配置
        setup_logging(args.verbose)    # 根据命令行的verbose 建立log文件

        # Create output directory
        output_dir = create_output(args.o, args.noclean)    # 建立输出的文件目录

        if args.verilog_style_check:                    #  如果有verilog_style 检查 ，调用 shell 运行：verilog_style/run.sh， 如果有返回值，则报错
            logging.debug("Run style check")
            style_err = run_cmd("verilog_style/run.sh")
            if style_err: logging.info(
                "Found style error: \nERROR: " + style_err)

        # Run any handcoded/directed assembly tests specified by args.asm_test
        if args.asm_test != "":                       # 是否为空字符串，如果不为空，表示需要执行定向汇编测试
            asm_test = args.asm_test.split(',')       # 将args.asm_test路径按逗号分隔成一个列表，保存在asm_test变量中
            for path_asm_test in asm_test:
                full_path = os.path.expanduser(path_asm_test)  # os.path.expanduser(path_asm_test)将相对路径转换为绝对路径，并保存在full_path变量中
                # path_asm_test is a directory
                if os.path.isdir(full_path):          # 如果是目录，调用run_assembly_from_dir函数来执行该目录下的所有汇编测试
                    run_assembly_from_dir(full_path, args.iss_yaml, args.isa,
                                          args.mabi,
                                          args.gcc_opts, args.iss, output_dir,
                                          args.core_setting_dir, args.debug)
                # path_asm_test is an assembly file
                elif os.path.isfile(full_path) or args.debug:    # 如果是汇编文件，或者当前处于调试模式（args.debug为True），调用run_assembly函数来执行该汇编文件
                    run_assembly(full_path, args.iss_yaml, args.isa, args.mabi,
                                 args.gcc_opts,
                                 args.iss, output_dir, args.core_setting_dir,
                                 args.debug)
                else:        # 既不是一个目录也不是一个汇编文件，说明指定的路径不存在
                    logging.error('{} does not exist'.format(full_path))
                    sys.exit(RET_FAIL)
            return

        # Run any handcoded/directed c tests specified by args.c_test
        if args.c_test != "":              # 同上一样，用的是c测试
            c_test = args.c_test.split(',')
            for path_c_test in c_test:
                full_path = os.path.expanduser(path_c_test)
                # path_c_test is a directory
                if os.path.isdir(full_path):
                    run_c_from_dir(full_path, args.iss_yaml, args.isa,
                                   args.mabi,
                                   args.gcc_opts, args.iss, output_dir,
                                   args.core_setting_dir, args.debug)
                # path_c_test is a c file
                elif os.path.isfile(full_path) or args.debug:
                    run_c(full_path, args.iss_yaml, args.isa, args.mabi,
                          args.gcc_opts,
                          args.iss, output_dir, args.core_setting_dir,
                          args.debug)
                else:
                    logging.error('{} does not exist'.format(full_path))
                    sys.exit(RET_FAIL)
            return

        run_cmd_output(["mkdir", "-p", ("{}/asm_test".format(output_dir))])     # 建立一个文件夹
        # Process regression test list
        matched_list = []   # 用于记录与指定条件匹配的测试列表
        # Any tests in the YAML test list that specify a directed assembly test  
        asm_directed_list = []   # 定向汇编测试的测试列表
        # Any tests in the YAML test list that specify a directed c test
        c_directed_list = []  # 用于记录指定了定向C测试的测试列表

        if not args.co:        # 如果不是仅编译，则
            process_regression_list(args.testlist, args.test, args.iterations,   # 从回归测试列表中获取匹配的测试
                                    matched_list, cwd)
            for t in list(matched_list):
                # Check mutual exclusive between gen_test, asm_test, and c_test
                if 'asm_test' in t:                # 如果是汇编测试
                    if 'gen_test' in t or 'c_test' in t:
                        logging.error(
                            'asm_test must not be defined in the testlist '
                            'together with the gen_test or c_test field')
                        sys.exit(RET_FATAL)
                    asm_directed_list.append(t)
                    matched_list.remove(t)

                if 'c_test' in t:      # 如果是c测试
                    if 'gen_test' in t or 'asm_test' in t:
                        logging.error(
                            'c_test must not be defined in the testlist '
                            'together with the gen_test or asm_test field')
                        sys.exit(RET_FATAL)
                    c_directed_list.append(t)
                    matched_list.remove(t)

            if len(matched_list) == 0 and len(asm_directed_list) == 0 and len(      # 找不到测试
                    c_directed_list) == 0:
                sys.exit("Cannot find {} in {}".format(args.test, args.testlist))

        # Run instruction generator         运行随机指令发生器
        if args.steps == "all" or re.match(".*gen.*", args.steps):    # 在步骤里有gen的选项
            # Run any handcoded/directed assembly tests specified in YAML format   #  运行以 YAML 格式指定的任何手写/定向汇编测试。
            if len(asm_directed_list) != 0:           # 定向汇编测试列表不为0
                for test_entry in asm_directed_list:
                    gcc_opts = args.gcc_opts           # 加一些选项
                    gcc_opts += test_entry.get('gcc_opts', '')
                    path_asm_test = os.path.expanduser(
                        test_entry.get('asm_test'))     
                    if path_asm_test:
                        # path_asm_test is a directory
                        if os.path.isdir(path_asm_test):      # 目录的跑
                            run_assembly_from_dir(path_asm_test, args.iss_yaml,
                                                  args.isa, args.mabi,
                                                  gcc_opts, args.iss,
                                                  output_dir,
                                                  args.core_setting_dir,
                                                  args.debug)
                        # path_asm_test is an assembly file
                        elif os.path.isfile(path_asm_test):   # 文件的跑
                            run_assembly(path_asm_test, args.iss_yaml, args.isa,
                                         args.mabi, gcc_opts,
                                         args.iss, output_dir,
                                         args.core_setting_dir, args.debug)
                        else:     # 否则报错
                            if not args.debug:
                                logging.error(
                                    '{} does not exist'.format(path_asm_test))
                                sys.exit(RET_FAIL)

            # Run any handcoded/directed C tests specified in YAML format
            if len(c_directed_list) != 0:      # 同上  c测试
                for test_entry in c_directed_list:
                    gcc_opts = args.gcc_opts
                    gcc_opts += test_entry.get('gcc_opts', '')
                    path_c_test = os.path.expanduser(test_entry.get('c_test'))
                    if path_c_test:
                        # path_c_test is a directory
                        if os.path.isdir(path_c_test):
                            run_c_from_dir(path_c_test, args.iss_yaml, args.isa,
                                           args.mabi,
                                           gcc_opts, args.iss, output_dir,
                                           args.core_setting_dir, args.debug)
                        # path_c_test is a C file
                        elif os.path.isfile(path_c_test):
                            run_c(path_c_test, args.iss_yaml, args.isa,
                                  args.mabi, gcc_opts,
                                  args.iss, output_dir, args.core_setting_dir,
                                  args.debug)
                        else:
                            if not args.debug:
                                logging.error('{} does not exist'.format(path_c_test))
                                sys.exit(RET_FAIL)

            # Run remaining tests using the instruction generator
            gen(matched_list, args, output_dir, cwd)   # 运行指令发生器

        if not args.co:    # 不是仅编译
            # Compile the assembly program to ELF, convert to plain binary   将汇编程序编译为 ELF 格式，转换为纯二进制格式。使用RISC-V GCC工具链编译汇编
            if args.steps == "all" or re.match(".*gcc_compile.*", args.steps):
                gcc_compile(matched_list, output_dir, args.isa, args.mabi,
                            args.gcc_opts, args.debug)

            # Run ISS simulation   使用 模拟器进行仿真
            if args.steps == "all" or re.match(".*iss_sim.*", args.steps):    
                iss_sim(matched_list, output_dir, args.iss, args.iss_yaml,
                        args.iss_opts,
                        args.isa, args.core_setting_dir, args.iss_timeout,
                        args.debug)

            # Compare ISS simulation result    进行仿真结果的比对
            if args.steps == "all" or re.match(".*iss_cmp.*", args.steps):
                iss_cmp(matched_list, args.iss, output_dir,
                        args.stop_on_first_error,
                        args.exp, args.debug)

        sys.exit(RET_SUCCESS)    # 程序退出
    except KeyboardInterrupt:   # ctrl-c 退出
        logging.info("\nExited Ctrl-C from user request.")
        sys.exit(130)


if __name__ == "__main__":
    main()
