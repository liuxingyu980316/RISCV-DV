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

Parse the regression testlist in YAML format
"""

import os
import random
import sys
import re
import subprocess
import time
import yaml
import logging
import signal

from datetime import date

RET_SUCCESS = 0
RET_FAIL    = 1
RET_FATAL   = -1


def setup_logging(verbose):  # 目的：用于设置日志的记录，根据verbose选择这个日志是DEBUG的还是INFO
    """Setup the root logger.

    Args:
      verbose: Verbose logging

    
    format: 定义日志记录的格式，asctime：时间  filename：源文件名称  lineno：源文件的行号  levelname：日志记录的级别  message：日志消息  -8s：超长的内容会被截取
    datefmt： '%a, %d %b %Y %H:%M:%S' 会输出像 'Mon, 06 Mar 2023 15:30:00' 这样的日期和时间格式
    level： 上述的 levelname的级别
    """
    if verbose:
        logging.basicConfig(
            format="%(asctime)s %(filename)s:%(lineno)-5s %(levelname)-8s %(message)s",
            datefmt='%a, %d %b %Y %H:%M:%S',
            level=logging.DEBUG)
    else:
        logging.basicConfig(format="%(asctime)s %(levelname)-8s %(message)s",
                            datefmt='%a, %d %b %Y %H:%M:%S',
                            level=logging.INFO)


def read_yaml(yaml_file):  #  目的：解析YAML文件并解析为Python字典
    """ Read YAML file to a dictionary

    Args:
      yaml_file : YAML file

    Returns:
      yaml_data : data read from YAML in dictionary format

   
    yaml_file: 是一个字符串，表示了yaml文件的路径

    with open: 打开指定的yaml文件并将内容读取到对象f中，“r”是只读打开，with 的作用是文件打开之后能正常的关闭
    try - except : 尝试进行文件解析，把f的yaml内容解析为Python的字典，并保存在yaml_data中
                   如果解析失败，记录错误至exc中，把exc保存在logging中，并退出程序，RET_FAIL 定义为 1
    """
    with open(yaml_file, "r") as f:
        try:
            yaml_data = yaml.safe_load(f)
        except yaml.YAMLError as exc:
            logging.error(exc)
            sys.exit(RET_FAIL)
    return yaml_data


def get_env_var(var, debug_cmd=None):  # 目的： 获取环境变量
    """Get the value of environment variable

    Args:
      var : Name of the environment variable

    Returns:
      val : Value of the environment variable

    
    var： 要获取的环境变量的名称，获取系统路径环境变量的值，var 一般是 "PATH"

    获取的环境变量保存至val 中并返回val值
    """
    try:
        val = os.environ[var]
    except KeyError:
        if debug_cmd:
            return var
        else:
            logging.warning("Please set the environment variable {}".format(var))
            sys.exit(RET_FAIL)
    return val


def run_cmd(cmd, timeout_s=999, exit_on_error=1, check_return_code=True,  # 目的： 执行shell命令并返回命令的输出
            debug_cmd=None):
    """Run a command and return output

    Args:
      cmd : shell command to run

    Returns:
      command output

    

    time_out 超时
    exit_on_error 错误时是否退出程序
    check_return_code 是否检查命令的返回码
    如果有debug_cmd，则把cmd写入文件，之后返回

    exec + cmd : 要执行的shell命令
    executable: shell命令的解释器
    universal_newlines=True：这个参数指定输出将使用通用的换行符（\n）来表示，而不是系统默认的换行符。这样可以使得输出在不同的操作系统上保持一致。
    start_new_session=True：这个参数指定在新的会话中执行命令。这样可以使得命令的执行环境与当前环境隔离，避免受到当前环境的影响。
    env=os.environ：这个参数指定命令的环境变量。在这里，使用os.environ来获取当前的环境变量，并将其传递给命令。
    stdout=subprocess.PIPE：这个参数指定命令的标准输出将被捕获，并可以通过communicate()方法来获取。
    stderr=subprocess.STDOUT：这个参数指定命令的标准错误输出将被捕获，并将其合并到标准输出中。这样可以通过communicate()方法一次性获取命令的所有输出。
    """
    logging.debug(cmd)
    if debug_cmd:
        debug_cmd.write(cmd)
        debug_cmd.write("\n\n")
        return
    try:
        ps = subprocess.Popen("exec " + cmd,
                              shell=True,
                              executable='/bin/bash',
                              universal_newlines=True,
                              start_new_session=True,
                              env=os.environ,
                              stdout=subprocess.PIPE,
                              stderr=subprocess.STDOUT)
    except subprocess.CalledProcessError:                   # 如果捕获到 subprocess.CalledProcessError 异常，说明命令执行出错。此时，函数将记录错误信息并使用 sys.exit(RET_FAIL) 方法退出程序。
        logging.error(ps.communicate()[0])
        sys.exit(RET_FAIL)
    except KeyboardInterrupt:                               # 如果捕获到 KeyboardInterrupt 异常，说明用户按下了Ctrl-C键来中断程序执行。此时，函数将记录信息并使用 sys.exit(130) 方法退出程序。
        logging.info("\nExited Ctrl-C from user request.")
        sys.exit(130)
    try:
        output = ps.communicate(timeout=timeout_s)[0]       # 如果命令执行超时，将引发 subprocess.TimeoutExpired 异常。
    except subprocess.TimeoutExpired:
        logging.error("Timeout[{}s]: {}".format(timeout_s, cmd))
        output = ""
        try:
            os.killpg(os.getpgid(ps.pid), signal.SIGTERM)
        except AttributeError: #killpg not available on windows
            ps.kill()
    rc = ps.returncode
    if rc and check_return_code and rc > 0:  # 如果设置了 check_return_code 参数为True，并且命令返回码大于0，函数将记录错误信息和输出，并根据 exit_on_error 参数的值来决定是否退出程序。
        logging.info(output)
        logging.error(
            "ERROR return code: {}/{}, cmd:{}".format(check_return_code, rc, cmd))
        if exit_on_error:
            sys.exit(RET_FAIL)
    logging.debug(output)       # 函数返回命令的输出，保存在变量 output 中。
    return output


def run_parallel_cmd(cmd_list, timeout_s=999, exit_on_error=0,   # 目的： 执行多个shell命令并返回命令的输出
                     check_return_code=True, debug_cmd=None):
    """Run a list of commands in parallel

    Args:
      cmd_list: command list

    Returns:
      command output
    """
    if debug_cmd:
        for cmd in cmd_list:
            debug_cmd.write(cmd)
            debug_cmd.write("\n\n")
        return
    children = []
    for cmd in cmd_list:
        ps = subprocess.Popen("exec " + cmd,
                              shell=True,
                              executable='/bin/bash',
                              universal_newlines=True,
                              start_new_session=True,
                              stdout=subprocess.PIPE,
                              stderr=subprocess.STDOUT)
        children.append(ps)
    for i in range(len(children)):
        logging.info("Command progress: {}/{}".format(i + 1, len(children)))
        logging.debug("Waiting for command: {}".format(cmd_list[i]))
        try:
            output = children[i].communicate(timeout=timeout_s)[0]
        except KeyboardInterrupt:
            logging.info("\nExited Ctrl-C from user request.")
            sys.exit(130)
        except subprocess.TimeoutExpired:
            logging.error("Timeout[{}s]: {}".format(timeout_s, cmd))
            try:
                os.killpg(os.getpgid(children[i].pid), signal.SIGTERM)
            except AttributeError: #killpg not available on windows
                children[i].kill()
        rc = children[i].returncode
        if rc and check_return_code and rc > 0:
            logging.info(output)
            logging.error("ERROR return code: {}, cmd:{}".format(rc, cmd))
            if exit_on_error:
                sys.exit(RET_FAIL)
        # Restore stty setting otherwise the terminal may go crazy
        os.system("stty sane")
        logging.debug(output)


def run_cmd_output(cmd, debug_cmd=None): #  目的： 在Python中执行Shell命令并返回命令输出
    """Run a command and return output
    Args:
      cmd          : Command line to execute
    """
    logging.debug(" ".join(cmd))
    if debug_cmd:
        debug_cmd.write(" ".join(cmd))
        debug_cmd.write("\n\n")
        return
    try:
        output = subprocess.check_output(cmd)  # 执行shell 命令并获得其输出
    except subprocess.CalledProcessError as exc:
        logging.debug(exc.output)
        raise exc   # 用 raise 语句重新抛出该异常。注意，这里的 raise exc 语句会将异常传递给上层调用者，因此上层调用者需要处理该异常。
        sys.exit(RET_FAIL)
    if output:
        logging.debug(output) # 函数返回命令的输出，保存在变量 output 中。注意，这里的 output 是二进制的输出数据，需要根据需要进行解码和处理。


def process_regression_list(testlist, test, iterations, matched_list,   #目的：从回归测试列表中获取匹配的测试
                            riscv_dv_root):
    """ Get the matched tests from the regression test list

    Args:
      testlist      : Regression test list
      test          : Test to run, "all" means all tests in the list
      iterations    : Number of iterations for each test
      riscv_dv_root : Root directory of RISCV-DV

    Returns:
      matched_list : A list of matched tests
    参数：
      testlist ： 回归测试列表
      test：要运行的测试，"all "表示列表中的所有测试
      iterations ： 每个测试的迭代次数
      riscv_dv_root : RISCV-DV 的根目录

    返回值
      matched_list ： 匹配测试的列表
    """
    logging.info(
        "Processing regression test list : {}, test: {}".format(testlist, test))   # 函数会记录一条信息，表明正在处理哪个回归测试列表和哪个测试。
    yaml_data = read_yaml(testlist)   #  目的：解析YAML文件并解析为Python字典
    mult_test = test.split(',')   # 如果输入的test参数包含多个测试（通过逗号分隔），把它们分割成一个列表保存在mult_test变量中
    for entry in yaml_data:
        if 'import' in entry:
            sub_list = re.sub('<riscv_dv_root>', riscv_dv_root, entry['import'])
            process_regression_list(sub_list, test, iterations, matched_list,
                                    riscv_dv_root) # 如果条目包含import字段，这意味着它可能要导入其他的测试列表。在这种情况下，使用正则表达式re.sub来替换<riscv_dv_root>为实际的RISCV-DV根目录，然后递归调用process_regression_list来处理这个导入的测试列表。
        else:
            if (entry['test'] in mult_test) or (test == "all"):
                if iterations > 0 and entry['iterations'] > 0:
                    entry['iterations'] = iterations
                if entry['iterations'] > 0:
                    logging.info("Found matched tests: {}, iterations:{}".format(
                      entry['test'], entry['iterations']))
                    matched_list.append(entry)  # 函数返回一个包含匹配的测试的列表，这个列表在函数中被命名为matched_list。这个列表会被添加到输入参数matched_list中，这样调用者可以在函数外部访问它


def create_output(output, noclean, prefix="out_"):  #用于创建一个输出目录
    """ Create output directory

  Args:
    output : Name of specified output directory
    noclean: Do not clean the output of the previous runs

  Returns:
    Output directory

    
    output：指定的输出目录的名称。
    noclean：一个布尔值，如果为False，则在创建新的输出目录之前会清除旧的输出目录。
    prefix：输出目录的前缀，默认值为"out_"。
  """
    # Create output directory
    if output is None:
        output = prefix + str(date.today())
    if noclean is False:
        os.system("rm -rf {}".format(output))

    logging.info("Creating output directory: {}".format(output))   #记录日志
    subprocess.run(["mkdir", "-p", output])     #创建output文件夹
    return output   #调用者可以使用这个返回值来引用或操作该输出目录。


def gpr_to_abi(gpr):    # 将通用寄存器转换为相应的 abi 名称
    """Convert a general purpose register to its corresponding abi name"""
    switcher = {       #定义了一个switcher的字典，将字符串键映射到其他的字符串值。例如，键 "x0" 映射到值 "zero"，键 "x1" 映射到值 "ra"，以此类推
        "x0" : "zero",
        "x1" : "ra",
        "x2" : "sp",
        "x3" : "gp",
        "x4" : "tp",
        "x5" : "t0",
        "x6" : "t1",
        "x7" : "t2",
        "x8" : "s0",
        "x9" : "s1",
        "x10": "a0",
        "x11": "a1",
        "x12": "a2",
        "x13": "a3",
        "x14": "a4",
        "x15": "a5",
        "x16": "a6",
        "x17": "a7",
        "x18": "s2",
        "x19": "s3",
        "x20": "s4",
        "x21": "s5",
        "x22": "s6",
        "x23": "s7",
        "x24": "s8",
        "x25": "s9",
        "x26": "s10",
        "x27": "s11",
        "x28": "t3",
        "x29": "t4",
        "x30": "t5",
        "x31": "t6",
        "f0" : "ft0",
        "f1" : "ft1",
        "f2" : "ft2",
        "f3" : "ft3",
        "f4" : "ft4",
        "f5" : "ft5",
        "f6" : "ft6",
        "f7" : "ft7",
        "f8" : "fs0",
        "f9" : "fs1",
        "f10": "fa0",
        "f11": "fa1",
        "f12": "fa2",
        "f13": "fa3",
        "f14": "fa4",
        "f15": "fa5",
        "f16": "fa6",
        "f17": "fa7",
        "f18": "fs2",
        "f19": "fs3",
        "f20": "fs4",
        "f21": "fs5",
        "f22": "fs6",
        "f23": "fs7",
        "f24": "fs8",
        "f25": "fs9",
        "f26": "fs10",
        "f27": "fs11",
        "f28": "ft8",
        "f29": "ft9",
        "f30": "ft10",
        "f31": "ft11",
    }
    return switcher.get(gpr, "na")   #尝试从 switcher 字典中获取与键 gpr 对应的值。如果 gpr 不在 switcher 字典中，它将返回默认值 "na"


def sint_to_hex(val):   #有符号整数到十六进制的转换
    """Signed integer to hex conversion"""
    return str(hex((val + (1 << 32)) % (1 << 32)))


BASE_RE = re.compile(
    r"(?P<rd>[a-z0-9]+?),(?P<imm>[\-0-9]*?)\((?P<rs1>[a-z0-9]+?)\)")

"""
     例如，对于字符串 "x1,-42(y2)"，这个正则表达式将匹配并提取出以下信息：
     "rd": "x1"  一个由小写字母和数字组成的字符串
     "imm": "-42"  一个由数字和破折号组成的字符串
     "rs1": "y2"   一个由小写字母和数字组成的字符串
"""


def convert_pseudo_instr(instr_name, operands, binary):      #将伪指令转化为实际的指令，这个函数为给定的伪指令提供了一种转换方法，将其转换为实际的RISC-V汇编指令
    """Convert pseudo instruction to regular instruction"""
    """instr_name（指令名称）、operands（操作数）和binary（二进制）""" 
    if instr_name == "nop":
        instr_name = "addi"
        operands = "zero,zero,0"
    elif instr_name == "mv":
        instr_name = "addi"
        operands = operands + ",0"
    elif instr_name == "not":
        instr_name = "xori"
        operands = operands + ",-1"
    elif instr_name == "neg":
        instr_name = "sub"
        o = operands.split(",")
        operands = o[0] + ",zero," + o[1]
    elif instr_name == "negw":
        instr_name = "subw"
        o = operands.split(",")
        operands = o[0] + ",zero," + o[1]
    elif instr_name == "sext.w":
        instr_name = "addiw"
        operands = operands + ",0"
    elif instr_name == "seqz":
        instr_name = "sltiu"
        operands = operands + ",1"
    elif instr_name == "snez":
        instr_name = "sltu"
        o = operands.split(",")
        operands = o[0] + ",zero," + o[1]
    elif instr_name == "sltz":
        instr_name = "slt"
        operands = operands + ",zero"
    elif instr_name == "sgtz":
        instr_name = "slt"
        o = operands.split(",")
        operands = o[0] + ",zero," + o[1]
    elif instr_name in ["beqz", "bnez", "bgez", "bltz"]:
        instr_name = instr_name[0:3]
        o = operands.split(",")
        operands = o[0] + ",zero," + o[1]
    elif instr_name == "blez":
        instr_name = "bge"
        operands = "zero," + operands
    elif instr_name == "bgtz":
        instr_name = "blt"
        operands = "zero," + operands
    elif instr_name == "bgt":
        instr_name = "blt"
        o = operands.split(",")
        operands = o[1] + "," + o[0] + "," + o[2]
    elif instr_name == "ble":
        instr_name = "bge"
        o = operands.split(",")
        operands = o[1] + "," + o[0] + "," + o[2]
    elif instr_name == "bgtu":
        instr_name = "bltu"
        o = operands.split(",")
        operands = o[1] + "," + o[0] + "," + o[2]
    elif instr_name == "bleu":
        instr_name = "bgeu"
        o = operands.split(",")
        operands = o[1] + "," + o[0] + "," + o[2]
    elif instr_name == "csrr":
        instr_name = "csrrw"
        operands = operands + ",zero"
    elif instr_name in ["csrw", "csrs", "csrc"]:
        instr_name = "csrr" + instr_name[3:]
        operands = "zero," + operands
    elif instr_name in ["csrwi", "csrsi", "csrci"]:
        instr_name = "csrr" + instr_name[3:]
        operands = "zero," + operands
    elif instr_name == "jr":
        instr_name = "jalr"
        operands = "zero,{},0".format(operands)
    elif instr_name == "j":
        instr_name = "jal"
        operands = "zero,{}".format(operands)
    elif instr_name == "jal":
        if not ("," in operands):
            operands = "ra,{}".format(operands)
    elif instr_name == "jalr":
        m = BASE_RE.search(operands)
        # jalr rd, imm(rs1)
        if m:
            operands = "{},{},{}".format(m.group("rd"), m.group("rs1"), m.group("imm"))
        # jalr rs1
        idx = operands.rfind(",")
        if idx == -1:
            operands = "ra," + operands + ",0"
    elif instr_name == "ret":
        if binary[-1] == "2":
            instr_name = "c.jr"
            operands = "ra"
        else:
            instr_name = "jalr"
            operands = "zero,ra,0"
    # RV32B pseudo instructions
    # TODO: support "rev", "orc", and "zip/unzip" instructions for RV64
    elif instr_name == "rev.p":
        instr_name = "grevi"
        operands += ",1"
    elif instr_name == "rev2.n":
        instr_name = "grevi"
        operands += ",2"
    elif instr_name == "rev.n":
        instr_name = "grevi"
        operands += ",3"
    elif instr_name == "rev4.b":
        instr_name = "grevi"
        operands += ",4"
    elif instr_name == "rev2.b":
        instr_name = "grevi"
        operands += ",6"
    elif instr_name == "rev.b":
        instr_name = "grevi"
        operands += ",7"
    elif instr_name == "rev8.h":
        instr_name = "grevi"
        operands += ",8"
    elif instr_name == "rev4.h":
        instr_name = "grevi"
        operands += ",12"
    elif instr_name == "rev2.h":
        instr_name = "grevi"
        operands += ",14"
    elif instr_name == "rev.h":
        instr_name = "grevi"
        operands += ",15"
    elif instr_name == "rev16":
        instr_name = "grevi"
        operands += ",16"
    elif instr_name == "rev8":
        instr_name = "grevi"
        operands += ",24"
    elif instr_name == "rev4":
        instr_name = "grevi"
        operands += ",28"
    elif instr_name == "rev2":
        instr_name = "grevi"
        operands += ",30"
    elif instr_name == "rev":
        instr_name = "grevi"
        operands += ",31"
    elif instr_name == "orc.p":
        instr_name = "gorci"
        operands += ",1"
    elif instr_name == "orc2.n":
        instr_name = "gorci"
        operands += ",2"
    elif instr_name == "orc.n":
        instr_name = "gorci"
        operands += ",3"
    elif instr_name == "orc4.b":
        instr_name = "gorci"
        operands += ",4"
    elif instr_name == "orc2.b":
        instr_name = "gorci"
        operands += ",6"
    elif instr_name == "orc.b":
        instr_name = "gorci"
        operands += ",7"
    elif instr_name == "orc8.h":
        instr_name = "gorci"
        operands += ",8"
    elif instr_name == "orc4.h":
        instr_name = "gorci"
        operands += ",12"
    elif instr_name == "orc2.h":
        instr_name = "gorci"
        operands += ",14"
    elif instr_name == "orc.h":
        instr_name = "gorci"
        operands += ",15"
    elif instr_name == "orc16":
        instr_name = "gorci"
        operands += ",16"
    elif instr_name == "orc8":
        instr_name = "gorci"
        operands += ",24"
    elif instr_name == "orc4":
        instr_name = "gorci"
        operands += ",28"
    elif instr_name == "orc2":
        instr_name = "gorci"
        operands += ",30"
    elif instr_name == "orc":
        instr_name = "gorci"
        operands += ",31"
    elif instr_name == "zext.b":
        instr_name = "andi"
        operands += ",255"
    elif instr_name == "zext.h":
        # TODO: support for RV64B
        instr_name = "pack"
        operands += ",zero"
    elif instr_name == "zext.w":
        instr_name = "pack"
        operands += ",zero"
    elif instr_name == "sext.w":
        instr_name = "addiw"
        operands += ",0"
    elif instr_name == "zip.n":
        instr_name = "shfli"
        operands += ",1"
    elif instr_name == "unzip.n":
        instr_name = "unshfli"
        operands += ",1"
    elif instr_name == "zip2.b":
        instr_name = "shfli"
        operands += ",2"
    elif instr_name == "unzip2.b":
        instr_name = "unshfli"
        operands += ",2"
    elif instr_name == "zip.b":
        instr_name = "shfli"
        operands += ",3"
    elif instr_name == "unzip.b":
        instr_name = "unshfli"
        operands += ",3"
    elif instr_name == "zip4.h":
        instr_name = "shfli"
        operands += ",4"
    elif instr_name == "unzip4.h":
        instr_name = "unshfli"
        operands += ",4"
    elif instr_name == "zip2.h":
        instr_name = "shfli"
        operands += ",6"
    elif instr_name == "unzip2.h":
        instr_name = "unshfli"
        operands += ",6"
    elif instr_name == "zip.h":
        instr_name = "shfli"
        operands += ",7"
    elif instr_name == "unzip.h":
        instr_name = "unshfli"
        operands += ",7"
    elif instr_name == "zip8":
        instr_name = "shfli"
        operands += ",8"
    elif instr_name == "unzip8":
        instr_name = "unshfli"
        operands += ",8"
    elif instr_name == "zip4":
        instr_name = "shfli"
        operands += ",12"
    elif instr_name == "unzip4":
        instr_name = "unshfli"
        operands += ",12"
    elif instr_name == "zip2":
        instr_name = "shfli"
        operands += ",14"
    elif instr_name == "unzip2":
        instr_name = "unshfli"
        operands += ",14"
    elif instr_name == "zip":
        instr_name = "shfli"
        operands += ",15"
    elif instr_name == "unzip":
        instr_name = "unshfli"
        operands += ",15"
    return instr_name, operands
