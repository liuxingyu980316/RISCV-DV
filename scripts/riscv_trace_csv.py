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

Class for RISC-V instruction trace CSV
"""

import csv
import re
import logging
import sys
from lib import *


class RiscvInstructionTraceEntry(object):   #定义了一个 RiscvInstructionTraceEntry 的新的类
    """RISC-V instruction trace entry"""

    def __init__(self):   # 类的初始化
        self.gpr = []    # 用于存储通用寄存器的更新。它是一个空列表。
        self.csr = []    # 用于存储控制和状态寄存器的更新。它也是一个空列表。
        self.instr = ""  # 指令的二进制表示。 
        self.operand = ""  # 存储指令的操作数。
        self.pc = ""    # 程序计数器的值
        self.binary = ""  # 指令的二进制字符串表示。
        self.instr_str = ""   # 指令的字符串表示。
        self.mode = ""  # 存储指令执行的模式（例如，用户模式、特权模式、优先级等）

    def get_trace_string(self):
        """Return a short string of the trace entry"""
        return ("pc[{}] {}: {} {}".format(
            self.pc, self.instr_str, " ".join(self.gpr), " ".join(self.csr)))  使用 PC 名称 通用寄存器 控制寄存器 进行简短的表示


class RiscvInstructionTraceCsv(object):
    """RISC-V instruction trace CSV class

    This class provides functions to read/write trace CSV
    """

    def __init__(self, csv_fd):
        self.csv_fd = csv_fd

    def start_new_trace(self):     # 将 fields 中的内容写入 CSV 的文件头中
        """Create a CSV file handle for a new trace"""
        fields = ["pc", "instr", "gpr", "csr", "binary", "mode", "instr_str",
                  "operand", "pad"]
        self.csv_writer = csv.DictWriter(self.csv_fd, fieldnames=fields)
        self.csv_writer.writeheader()

    def read_trace(self, trace):    # 把CSV中的内容按行读取后 存入 trace中
        """Read instruction trace from CSV file"""
        csv_reader = csv.DictReader(self.csv_fd)
        for row in csv_reader:
            new_trace = RiscvInstructionTraceEntry()
            new_trace.gpr = row['gpr'].split(';')
            new_trace.csr = row['csr'].split(';')
            new_trace.pc = row['pc']
            new_trace.operand = row['operand']
            new_trace.binary = row['binary']
            new_trace.instr_str = row['instr_str']
            new_trace.instr = row['instr']
            new_trace.mode = row['mode']
            trace.append(new_trace)     

    # TODO: Convert pseudo instruction to regular instruction

    def write_trace_entry(self, entry):  # 通过调用 write_trace_entry 方法，可以将一个新的跟踪条目entry写入 CSV 文件，而无需手动处理 CSV 文件的格式和写入细节
        """Write a new trace entry to CSV"""
        self.csv_writer.writerow({'instr_str': entry.instr_str,
                                  'gpr'      : ";".join(entry.gpr),  # 由于它们是列表，所以在写入 CSV 文件之前需要使用 ";".join() 方法将它们转换为以分号分隔的字符串。
                                  'csr'      : ";".join(entry.csr),
                                  'operand'  : entry.operand,
                                  'pc'       : entry.pc,
                                  'binary'   : entry.binary,
                                  'instr'    : entry.instr,
                                  'mode'     : entry.mode})


def get_imm_hex_val(imm):   # 按照 是否是 负数进行 立即数的处理，处理成十六进制
    """Get the hex representation of the imm value"""
    if imm[0] == '-':
        is_negative = 1
        imm = imm[1:]
    else:
        is_negative = 0
    imm_val = int(imm, 0)
    if is_negative:
        imm_val = -imm_val
    hexstr = sint_to_hex(imm_val)
    return hexstr[2:]
