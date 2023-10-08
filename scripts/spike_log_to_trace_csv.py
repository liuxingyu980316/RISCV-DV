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

Convert spike sim log to standard riscv instruction trace format
将spike 模拟器日志转化为标准的RISCV指令跟踪格式：这种格式包含了一系列的标准字段，如指令地址、操作码、操作数等，可以方便地进行指令级别的分析和调试
"""

import argparse
import os
import re
import sys
import logging

sys.path.insert(0, os.path.dirname(os.path.realpath(__file__)))    #这行代码的目的是将当前正在执行的Python脚本所在的目录添加到Python解释器的模块搜索路径中，并且让它成为第一个搜索的目录。这样，就可以在当前目录下导入其他Python模块。

from riscv_trace_csv import *
from lib import *

RD_RE = re.compile(       #它提取的信息包括：优先级（pri）、地址（addr）、二进制表示（bin）、寄存器（reg）、值（val）、控制状态寄存器（csr）和控制状态寄存器的值（csr_val）
    r"(core\s+\d+:\s+)?(?P<pri>\d)\s+0x(?P<addr>[a-f0-9]+?)\s+" \
    r"\((?P<bin>.*?)\)\s+(?P<reg>[xf]\s*\d*?)\s+0x(?P<val>[a-f0-9]+)" \
    r"(\s+(?P<csr>\S+)\s+0x(?P<csr_val>[a-f0-9]+))?")
CORE_RE = re.compile(    #它提取的信息包括：地址（addr）、二进制表示（bin）和指令（instr）
    r"core\s+\d+:\s+0x(?P<addr>[a-f0-9]+?)\s+\(0x(?P<bin>.*?)\)\s+(?P<instr>.*?)$")
ADDR_RE = re.compile(    #它提取的信息包括：寄存器（rd）、立即数（imm）和寄存器（rs1）
    r"(?P<rd>[a-z0-9]+?),(?P<imm>[\-0-9]+?)\((?P<rs1>[a-z0-9]+)\)")
ILLE_RE = re.compile(r"trap_illegal_instruction") #它提取的信息包括：非法指令

LOGGER = logging.getLogger()    #创建或者获取一个”root“的日志记录器


def process_instr(trace):    #目的：将一个指令的操作数转化为CSV格式
    if trace.instr == "jal":
        # Spike jal format jal rd, -0xf -> jal rd, -15     jump and link 指令
        idx = trace.operand.rfind(",")   # 在trace对象的operand 中找到最后一个逗号的位置，赋值给idx 例如x10,0x1234(x11) “7”
        imm = trace.operand[idx + 1:] #从最后一个逗号开始，提取出立即数
        if imm[0] == "-":   #判断立即数的第一个字符是否为 “-”
            imm = "-" + str(int(imm[1:], 16))   #如果立即数是负数，将其转换为十进制整数，并保留负号。
        else:
            imm = str(int(imm, 16))  #将立即数转换为十进制整数，并转换为字符串类型
        trace.operand = trace.operand[0:idx + 1] + imm    #将处理后的立即数重新组合到operand属性中，替换原来的operand部分。
    # Properly format operands of all instructions of the form:
    # <instr> <reg1> <imm>(<reg2>)
    # The operands should be converted into CSV as:
    # "<reg1>,<reg2>,<imm>"
    m = ADDR_RE.search(trace.operand)  #使用寄存器（rd）、立即数（imm）和寄存器（rs1） 进行匹配
    if m:
        trace.operand = "{},{},{}".format(   #匹配成功，则用， ， ， 的CSV格式替换原来的operand格式
            m.group("rd"), m.group("rs1"), m.group("imm"))


def read_spike_instr(match, full_trace):    # 将正则表达式匹配后的对象 解析为一个RiscvInstructionTraceEntry对象，包含了指令的各种属性，如程序计数器 PC 指令字符串 二进制表示等
    """Unpack a regex match for CORE_RE to a RiscvInstructionTraceEntry

    If full_trace is true, extract operand data from the disassembled instruction.

    """

    # Extract the disassembled instruction.
    disasm = match.group('instr')          #从正则表达式匹配的对象match中的instr组的结果给disasm， instr的使用例子见61行：m.group("rd"), m.group("rs1"), m.group("imm"))

    # Spike's disassembler shows a relative jump as something like "j pc + 0x123" or "j pc - 0x123". We just want the relative offset.
    disasm = disasm.replace('pc + ', '').replace('pc - ', '-')   #对反汇编后的指令字符串进行处理，将"pc + "替换为空字符串，将"pc - "替换为-。这是为了处理Spike模拟器中相对跳转指令的特殊表示方式

    instr = RiscvInstructionTraceEntry()     #从match的正则表达式中把对应的部分提取到RiscvInstructionTraceEntry instr变量中
    instr.pc = match.group('addr')
    instr.instr_str = disasm
    instr.binary = match.group('bin')

    if full_trace:   #full_trace为True时，可以从反汇编的指令中提取出更详细的信息，包括操作数数据，以便进行更复杂的数据处理和分析。而如果full_trace为False，则只会提取基本的指令跟踪信息，不会处理操作数数据。
        opcode = disasm.split(' ')[0]   #将反汇编指令字符串（disasm）按空格分割，并取第一个分割结果作为操作码（opcode）例：disasm的值为"addi x1, x2, 123"，其中"addi"是操作码，"x1, x2, 123"是操作数。
                                        #调用disasm.split(' ')会将字符串按空格分割成["addi", "x1,", "x2,", "123"]的列表。然后，通过索引列表的第一个元素，即[0]，可以提取出操作码"addi"
        operand = disasm[len(opcode):].replace(' ', '')  #len(opcode)会返回addi操作码的长度为4，然后使用切片操作disasm[4:]可以提取出操作数部分"x1, x2, 123"。 再删掉空格
        instr.instr, instr.operand = \
            convert_pseudo_instr(opcode, operand, instr.binary) #利用convert_pseudo_instr 函数将结果给instr的instr 和 operand

        process_instr(instr) #调用前序函数对信息进行处理和CSV化

    return instr


def read_spike_trace(path, full_trace):   #目的：从Spike模拟器的日志文件中读取指令
    """Read a Spike simulation log at <path>, yielding executed instructions.

    This assumes that the log was generated with the -l and --log-commits options
    to Spike.

    If full_trace is true, extract operands from the disassembled instructions.

    Since Spike has a strange trampoline that always runs at the start, we skip
    instructions up to and including the one at PC 0x1010 (the end of the
    trampoline). At the end of a DV program, there's an ECALL instruction, which
    we take as a signal to stop checking, so we ditch everything that follows
    that instruction.

    This function yields instructions as it parses them as tuples of the form
    (entry, illegal). entry is a RiscvInstructionTraceEntry. illegal is a
    boolean, which is true if the instruction caused an illegal instruction trap.

    这个模拟器模拟了一种叫做RISC-V的硬件的行为，那么这个日志会告诉你哪些指令被执行了。这就像是你在做一道菜，然后记录下了每一步的做法。
    这个日志里有很多的信息，包括每一步做了什么，以及是否有错误发生。如果你想知道每一步的详细信息，比如用了哪些原料，那么你就需要打开"full_trace"这个选项。
    但是，因为Spike在开始的时候运行了一些特殊的步骤，所以我们不需要关心这些步骤。我们只需要从0x1010这个地方开始看就行了。这就像是你在看一个食谱，但是你只需要从"准备原料"这一步开始看。
    最后，如果一个指令导致了错误，我们就知道这个指令是非法的，我们会在结果中标记出来。这样就像是你在看一个食谱，如果发现某一步做不了，你就会在这一步旁边打个问号。

    """

    # This loop is a simple FSM with states TRAMPOLINE, INSTR, EFFECT. The idea
    # is that we're in state TRAMPOLINE until we get to the end of Spike's
    # trampoline, then we switch between INSTR (where we expect to read an
    # instruction) and EFFECT (where we expect to read commit information).
    #
    # We yield a RiscvInstructionTraceEntry object each time we leave EFFECT
    # (going back to INSTR), we loop back from INSTR to itself, or we get to the
    # end of the file and have an instruction in hand.
    #
    # On entry to the loop body, we are in state TRAMPOLINE if in_trampoline is
    # true. Otherwise, we are in state EFFECT if instr is not None, otherwise we
    # are in state INSTR.

    end_trampoline_re = re.compile(r'core.*: 0x0*1010 ')     #定义了一个正则表达式，用于匹配需要关心的起点：即0X1010

    in_trampoline = True     # 默认需要跳过
    instr = None     # 初始化一个变量，用于存储当前正在处理的指令

    with open(path, 'r') as handle:     #  根据PATH以只读模式打开spike日志文件
        for line in handle:             
            if in_trampoline:           #  当需要跳过的时候
                # The TRAMPOLINE state   
                if end_trampoline_re.match(line):   
                    in_trampoline = False
                continue                # 匹配每一行，直到匹配到OX1010，才进行下面的if语句

            if instr is None: 
                # The INSTR state. We expect to see a line matching CORE_RE.
                # We'll discard any other lines.
                instr_match = CORE_RE.match(line)  #提取的信息包括：地址（addr）、二进制表示（bin）和指令（instr）
                if not instr_match:
                    continue

                instr = read_spike_instr(instr_match, full_trace)   #将提取到的信息转换成CSV 

                # If instr.instr_str is 'ecall', we should stop.
                if instr.instr_str == 'ecall':
                    break

                continue

            # The EFFECT state. If the line matches CORE_RE, we should have been in
            # state INSTR, so we yield the instruction we had, read the new
            # instruction and continue. As above, if the new instruction is 'ecall',
            # we need to stop immediately.
            instr_match = CORE_RE.match(line)
            if instr_match:
                yield instr, False
                instr = read_spike_instr(instr_match, full_trace)
                if instr.instr_str == 'ecall':
                    break
                continue

            # The line doesn't match CORE_RE, so we are definitely on a follow-on
            # line in the log. First, check for illegal instructions
            if 'trap_illegal_instruction' in line:
                yield (instr, True)
                instr = None
                continue

            # The instruction seems to have been fine. Do we have commit data (from
            # the --log-commits Spike option)?
            commit_match = RD_RE.match(line)
            if commit_match:
                groups = commit_match.groupdict()     #存到字典中
                instr.gpr.append(gpr_to_abi(groups["reg"].replace(' ', '')) +
                                 ":" + groups["val"])

                if groups["csr"] and groups["csr_val"]:
                    instr.csr.append(groups["csr"] + ":" + groups["csr_val"])

                instr.mode = commit_match.group('pri')

        # At EOF, we might have an instruction in hand. Yield it if so.
        if instr is not None:
            yield (instr, False)


def process_spike_sim_log(spike_log, csv, full_trace=0):
    """Process SPIKE simulation log.

    Extract instruction and affected register information from spike simulation
    log and write the results to a CSV file at csv. Returns the number of
    instructions written.

    """
    logging.info("Processing spike log : {}".format(spike_log))
    instrs_in = 0
    instrs_out = 0

    with open(csv, "w") as csv_fd:
        trace_csv = RiscvInstructionTraceCsv(csv_fd)
        trace_csv.start_new_trace()

        for (entry, illegal) in read_spike_trace(spike_log, full_trace):
            instrs_in += 1

            if illegal and full_trace:
                logging.debug("Illegal instruction: {}, opcode:{}"
                              .format(entry.instr_str, entry.binary))

            # Instructions that cause no architectural update (which includes illegal
            # instructions) are ignored if full_trace is false.
            #
            # We say that an instruction caused an architectural update if either we
            # saw a commit line (in which case, entry.gpr will contain a single
            # entry) or the instruction was 'wfi' or 'ecall'.
            if not (full_trace or entry.gpr or entry.instr_str in ['wfi',
                                                                   'ecall']):
                continue

            trace_csv.write_trace_entry(entry)
            instrs_out += 1

    logging.info("Processed instruction count : {}".format(instrs_in))
    logging.info("CSV saved to : {}".format(csv))
    return instrs_out


def main():
    # Parse input arguments
    parser = argparse.ArgumentParser()
    parser.add_argument("--log", type=str, help="Input spike simulation log")
    parser.add_argument("--csv", type=str, help="Output trace csv_buf file")
    parser.add_argument("-f", "--full_trace", dest="full_trace",
                        action="store_true",
                        help="Generate the full trace")
    parser.add_argument("-v", "--verbose", dest="verbose", action="store_true",
                        help="Verbose logging")
    parser.set_defaults(full_trace=False)
    parser.set_defaults(verbose=False)
    args = parser.parse_args()
    setup_logging(args.verbose)
    # Process spike log
    process_spike_sim_log(args.log, args.csv, args.full_trace)


if __name__ == "__main__":
    main()
