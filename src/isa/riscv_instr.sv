/*
 * Copyright 2019 Google LLC
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

class riscv_instr extends uvm_object;

  // All derived instructions    派生的指令
  static bit                 instr_registry[riscv_instr_name_t];           // 记录所有已注册的指令名称

  // Instruction list
  static riscv_instr_name_t  instr_names[$];                               // 存储所有指令的名称

  // Categorized instruction list
  static riscv_instr_name_t  instr_group[riscv_instr_group_t][$];          // riscv_instr_group_t表示指令组的类型 通常用于区分不同类型的指令，比如算术指令、逻辑指令
  static riscv_instr_name_t  instr_category[riscv_instr_category_t][$];    //  是对指令更加细致的划分，通常在同一组内，指令可以按照不同的类别进行进一步分类，比如移位指令、比较指令等
  static riscv_instr_name_t  basic_instr[$];                               //  基本指令的列表
  static riscv_instr         instr_template[riscv_instr_name_t];


  riscv_instr_gen_config     m_cfg;       //   配置

  // Instruction attributes
  riscv_instr_group_t        group;      //   指令的分组或类别
  riscv_instr_format_t       format;     //  指令的格式或结构
  riscv_instr_category_t     category;   //  指令的更大范围的分类
  riscv_instr_name_t         instr_name;  //  指令的名字
  imm_t                      imm_type;    //  指令的立即数
  bit [4:0]                  imm_len;     //  立即数的长度

  // Operands
  rand bit [11:0]            csr;   //  控制状态寄存器（Control Status Register）的地址
  rand riscv_reg_t           rs2;   //  RISC-V指令的第二个源操作数寄存器
  rand riscv_reg_t           rs1;   //  RISC-V指令的第一个源操作数寄存器
  rand riscv_reg_t           rd;    //  RISC-V指令的目的操作数寄存器
  rand bit [31:0]            imm;   //  RISC-V指令的立即数

  // Helper fields
  bit [31:0]                 imm_mask = 32'hFFFF_FFFF;    //  立即数的掩码
  bit                        is_branch_target;            //  表示当前指令是否是分支
  bit                        has_label = 1'b1;            //  表示指令是否有标签
  bit                        atomic = 0;                  //  是否是原子操作
  bit                        branch_assigned;             //  表示分支是否已分配
  bit                        process_load_store = 1'b1;   //  是否加载和存储指令
  bit                        is_compressed;               //  是否是压缩格式
  bit                        is_illegal_instr;            //  指令是否是非法指令
  bit                        is_hint_instr;               //  是否是提示指令
  bit                        is_floating_point;           //  是否是浮点指令
  string                     imm_str;                     //  用于存储立即数的字符串表示
  string                     comment;                     //  指令的注释
  string                     label;                       //  存储指令的标签
  bit                        is_local_numeric_label;      //  标签是否是本地数字标签
  int                        idx = -1;                    //  指令的索引或位置
  bit                        has_rs1 = 1'b1;              //  指令是否有第一个源操作数寄存器（rs1）
  bit                        has_rs2 = 1'b1;              //  指令是否有第二个源操作数寄存器（rs2）
  bit                        has_rd = 1'b1;               //  指令是否有目的操作数寄存器（rd）
  bit                        has_imm = 1'b1;              //  指令是否有立即数

  constraint imm_c {
    if (instr_name inside {SLLIW, SRLIW, SRAIW}) {
      imm[11:5] == 0;
    }
    if (instr_name inside {SLLI, SRLI, SRAI}) {
      if (XLEN == 32) {       // 寄存器数量
        imm[11:5] == 0;
      } else {
        imm[11:6] == 0;
      }
    }
  }


  `uvm_object_utils(riscv_instr)
  `uvm_object_new

  static function bit register(riscv_instr_name_t instr_name);  // 把instr_name 在instr_registry中登记起来
    `uvm_info("riscv_instr", $sformatf("Registering %0s", instr_name.name()), UVM_LOW)
    instr_registry[instr_name] = 1;
    return 1;
  endfunction : register

  // Create the list of instructions based on the supported ISA extensions and configuration of the  根据支持的ISA扩展和生成器的配置创建指令列表
  // generator.
  static function void create_instr_list(riscv_instr_gen_config cfg);
    instr_names.delete();
    instr_group.delete();
    instr_category.delete();
    foreach (instr_registry[instr_name]) begin      // 先使用上面的那个函数登记起来，登记为1的才会进入循环
      riscv_instr instr_inst;
      if (instr_name inside {unsupported_instr}) continue;
      instr_inst = create_instr(instr_name);      //  创建一个riscv_instr 类型的对象，创建名为 instr_name 的指令对象
      instr_template[instr_name] = instr_inst;    //  代码将 instr_inst 添加到 instr_template 数组中，以 instr_name 作为键。instr_template 数组就存储了创建的指令对象，以便后续使用
      if (!instr_inst.is_supported(cfg)) continue; //  利用cfg 判断这个instr是否被支持, 这个函数永远return 1
      // C_JAL is RV32C only instruction
      if ((XLEN != 32) && (instr_name == C_JAL)) continue;   //  出现了这种情况就continue  C_JAL 指令是 RV32C 的专有指令
      if ((SP inside {cfg.reserved_regs}) && (instr_name inside {C_ADDI16SP})) begin   //  因为 C_ADDI16SP 指令使用了 SP 寄存器，如果 SP 寄存器被保留，就需要跳过该指令。
        continue;
      end
      if (!cfg.enable_sfence && instr_name == SFENCE_VMA) continue;     //   sfence 指令的跳过
      if (cfg.no_fence && (instr_name inside {FENCE, FENCE_I, SFENCE_VMA})) continue;   //  fence 指令的跳过
      if ((instr_inst.group inside {supported_isa}) &&     // 成功的指令： 在指令列表里
          !(cfg.disable_compressed_instr &&                // 跳过的指令：非压缩但 RV32C, RV64C, RV32DC, RV32FC, RV128C
            (instr_inst.group inside {RV32C, RV64C, RV32DC, RV32FC, RV128C})) &&
          !(!cfg.enable_floating_point &&         // 跳过的指令： 非浮点，但 RV32F, RV64F, RV32D, RV64D
            (instr_inst.group inside {RV32F, RV64F, RV32D, RV64D})) &&
          !(!cfg.enable_vector_extension &&     // 跳过的指令： 非向量拓展 但 RVV指令
            (instr_inst.group inside {RVV})) &&
          !(cfg.vector_instr_only &&            // 跳过的指令： 仅向量拓展 但 不是RVV指令
            !(instr_inst.group inside {RVV}))
         ) begin                                                       //  instr_inst 其实就是 instr_name 的拓展
        instr_category[instr_inst.category].push_back(instr_name);    // 添加到 instr_category 数据结构中，该结构以 instr_inst.category 作为键
        instr_group[instr_inst.group].push_back(instr_name);    //  将 instr_name 添加到 instr_group 数据结构中，该结构以 instr_inst.group 作为键
        instr_names.push_back(instr_name);                       //   instr_name 添加到一个名为 instr_names 的列表中
      end 
    end
    build_basic_instruction_list(cfg);    //  形成 basic_指令的类别列表
  endfunction : create_instr_list

  virtual function bit is_supported(riscv_instr_gen_config cfg);
    return 1;
  endfunction

      static function riscv_instr create_instr(riscv_instr_name_t instr_name);   //  创建一个riscv_instr 类型的对象，创建名为 instr_name 的指令对象  instr_inst 其实就是 instr_name 的拓展
    uvm_object obj;
    riscv_instr inst;
    string instr_class_name;
    uvm_coreservice_t coreservice = uvm_coreservice_t::get();
    uvm_factory factory = coreservice.get_factory();
    instr_class_name = {"riscv_", instr_name.name(), "_instr"};
    obj = factory.create_object_by_name(instr_class_name, "riscv_instr", instr_class_name);
    if (obj == null) begin
      `uvm_fatal("riscv_instr", $sformatf("Failed to create instr: %0s", instr_class_name))
    end
    if (!$cast(inst, obj)) begin
      `uvm_fatal("riscv_instr", $sformatf("Failed to cast instr: %0s", instr_class_name))
    end
    return inst;
  endfunction : create_instr

      static function void build_basic_instruction_list(riscv_instr_gen_config cfg);  //  形成 basic_指令的类别列表
    basic_instr = {instr_category[SHIFT], instr_category[ARITHMETIC],    // 移位运算指令 算术运算指令  逻辑运算指令  比较指令
                   instr_category[LOGICAL], instr_category[COMPARE]};
    //  根据 cfg的指令，把指令添加到上述的列表中
    if (!cfg.no_ebreak) begin
      basic_instr = {basic_instr, EBREAK};       //  在basic_instr后面新增 EBREAK
      foreach (riscv_instr_pkg::supported_isa[i]) begin
        if (RV32C inside {riscv_instr_pkg::supported_isa[i]} &&
            !cfg.disable_compressed_instr) begin
          basic_instr = {basic_instr, C_EBREAK};   //  在basic_instr后面新增 C_EBREAK
          break;
        end
      end
    end
    if (!cfg.no_ecall) begin
      basic_instr = {basic_instr, ECALL};     //  将 ECALL 指令添加到 basic_instr 列表中。
    end
    if (cfg.no_dret == 0) begin
      basic_instr = {basic_instr, DRET};      //  将 DRET 指令添加到 basic_instr 列表中。
    end
    if (cfg.no_fence == 0) begin
      basic_instr = {basic_instr, instr_category[SYNCH]};   //  将 SYNCH类的 指令添加到 basic_instr 列表中。
    end
    if ((cfg.no_csr_instr == 0) && (cfg.init_privileged_mode == MACHINE_MODE)) begin  //  特权模式为机器模式且有csr_instr   将 CSR 类别的指令添加到 basic_instr
      basic_instr = {basic_instr, instr_category[CSR]};
    end
    if (cfg.no_wfi == 0) begin
      basic_instr = {basic_instr, WFI};     //   将 WFI 指令添加到 basic_instr 列表中。
    end
  endfunction : build_basic_instruction_list

  static function riscv_instr get_rand_instr(riscv_instr instr_h = null,
                                             riscv_instr_name_t include_instr[$] = {},
                                             riscv_instr_name_t exclude_instr[$] = {},
                                             riscv_instr_category_t include_category[$] = {},
                                             riscv_instr_category_t exclude_category[$] = {},
                                             riscv_instr_group_t include_group[$] = {},
                                             riscv_instr_group_t exclude_group[$] = {});
     int unsigned idx;
     riscv_instr_name_t name;
     riscv_instr_name_t allowed_instr[$];
     riscv_instr_name_t disallowed_instr[$];
     riscv_instr_category_t allowed_categories[$];
     foreach (include_category[i]) begin
       allowed_instr = {allowed_instr, instr_category[include_category[i]]};
     end
     foreach (exclude_category[i]) begin
       if (instr_category.exists(exclude_category[i])) begin
         disallowed_instr = {disallowed_instr, instr_category[exclude_category[i]]};
       end
     end
     foreach (include_group[i]) begin
       allowed_instr = {allowed_instr, instr_group[include_group[i]]};
     end
     foreach (exclude_group[i]) begin
       if (instr_group.exists(exclude_group[i])) begin
         disallowed_instr = {disallowed_instr, instr_group[exclude_group[i]]};
       end
     end
     disallowed_instr = {disallowed_instr, exclude_instr};
     if (disallowed_instr.size() == 0) begin
       if (include_instr.size() > 0) begin
         idx = $urandom_range(0, include_instr.size()-1);
         name = include_instr[idx];
       end else if (allowed_instr.size() > 0) begin
         idx = $urandom_range(0, allowed_instr.size()-1);
         name = allowed_instr[idx];
       end else begin
         idx = $urandom_range(0, instr_names.size()-1);
         name = instr_names[idx];
       end
     end else begin
       if (!std::randomize(name) with {
          name inside {instr_names};
          if (include_instr.size() > 0) {
            name inside {include_instr};
          }
          if (allowed_instr.size() > 0) {
            name inside {allowed_instr};
          }
          if (disallowed_instr.size() > 0) {
            !(name inside {disallowed_instr});
          }
       }) begin
         `uvm_fatal("riscv_instr", "Cannot generate random instruction")
       end
     end
     // Shallow copy for all relevant fields, avoid using create() to improve performance
     instr_h = new instr_template[name];
     return instr_h;
  endfunction : get_rand_instr

  static function riscv_instr get_load_store_instr(riscv_instr_name_t load_store_instr[$] = {});
     riscv_instr instr_h;
     int unsigned idx;
     int unsigned i;
     riscv_instr_name_t name;
     if (load_store_instr.size() == 0) begin
       load_store_instr = {instr_category[LOAD], instr_category[STORE]};
     end
     // Filter out unsupported load/store instruction
     if (unsupported_instr.size() > 0) begin
       while (i < load_store_instr.size()) begin
         if (load_store_instr[i] inside {unsupported_instr}) begin
           load_store_instr.delete(i);
         end else begin
           i++;
         end
       end
     end
     if (load_store_instr.size() == 0) begin
       $error("Cannot find available load/store instruction");
       $fatal(1);
     end
     idx = $urandom_range(0, load_store_instr.size()-1);
     name = load_store_instr[idx];
     // Shallow copy for all relevant fields, avoid using create() to improve performance
     instr_h = new instr_template[name];
     return instr_h;
  endfunction : get_load_store_instr

  static function riscv_instr get_instr(riscv_instr_name_t name);
     riscv_instr instr_h;
     if (!instr_template.exists(name)) begin
       `uvm_fatal("riscv_instr", $sformatf("Cannot get instr %0s", name.name()))
     end
     // Shallow copy for all relevant fields, avoid using create() to improve performance
     instr_h = new instr_template[name];
     return instr_h;
  endfunction : get_instr

  // Disable the rand mode for unused operands to randomization performance
  virtual function void set_rand_mode();
    case (format) inside
      R_FORMAT : has_imm = 1'b0;
      I_FORMAT : has_rs2 = 1'b0;
      S_FORMAT, B_FORMAT : has_rd = 1'b0;
      U_FORMAT, J_FORMAT : begin
        has_rs1 = 1'b0;
        has_rs2 = 1'b0;
      end
    endcase
  endfunction

  function void pre_randomize();
    rs1.rand_mode(has_rs1);
    rs2.rand_mode(has_rs2);
    rd.rand_mode(has_rd);
    imm.rand_mode(has_imm);
    if (category != CSR) begin
      csr.rand_mode(0);
    end
  endfunction

  virtual function void set_imm_len();
    if(format inside {U_FORMAT, J_FORMAT}) begin
      imm_len = 20;
    end else if(format inside {I_FORMAT, S_FORMAT, B_FORMAT}) begin
      if(imm_type == UIMM) begin
        imm_len = 5;
      end else begin
        imm_len = 12;
      end
    end
    imm_mask = imm_mask << imm_len;
  endfunction

  virtual function void extend_imm();
    bit sign;
    imm = imm << (32 - imm_len);
    sign = imm[31];
    imm = imm >> (32 - imm_len);
    // Signed extension
    if (sign && !((format == U_FORMAT) || (imm_type inside {UIMM, NZUIMM}))) begin
      imm = imm_mask | imm;
    end
  endfunction : extend_imm

  function void post_randomize();
    extend_imm();
    update_imm_str();
  endfunction : post_randomize

  // Convert the instruction to assembly code
  virtual function string convert2asm(string prefix = "");
    string asm_str;
    asm_str = format_string(get_instr_name(), MAX_INSTR_STR_LEN);
    if(category != SYSTEM) begin
      case(format)
        J_FORMAT, U_FORMAT : // instr rd,imm
          asm_str = $sformatf("%0s%0s, %0s", asm_str, rd.name(), get_imm());
        I_FORMAT: // instr rd,rs1,imm
          if(instr_name == NOP)
            asm_str = "nop";
          else if(instr_name == WFI)
            asm_str = "wfi";
          else if(instr_name == FENCE)
            asm_str = $sformatf("fence"); // TODO: Support all fence combinations
          else if(instr_name == FENCE_I)
            asm_str = "fence.i";
          else if(category == LOAD) // Use psuedo instruction format
            asm_str = $sformatf("%0s%0s, %0s(%0s)", asm_str, rd.name(), get_imm(), rs1.name());
          else
            asm_str = $sformatf("%0s%0s, %0s, %0s", asm_str, rd.name(), rs1.name(), get_imm());
        S_FORMAT, B_FORMAT: // instr rs1,rs2,imm
          if(category == STORE) // Use psuedo instruction format
            asm_str = $sformatf("%0s%0s, %0s(%0s)", asm_str, rs2.name(), get_imm(), rs1.name());
          else
            asm_str = $sformatf("%0s%0s, %0s, %0s", asm_str, rs1.name(), rs2.name(), get_imm());
        R_FORMAT: // instr rd,rs1,rs2
          if(instr_name == SFENCE_VMA) begin
            asm_str = "sfence.vma x0, x0"; // TODO: Support all possible sfence
          end else begin
            asm_str = $sformatf("%0s%0s, %0s, %0s", asm_str, rd.name(), rs1.name(), rs2.name());
          end
        default: `uvm_fatal(`gfn, $sformatf("Unsupported format %0s [%0s]",
                                            format.name(), instr_name.name()))
      endcase
    end else begin
      // For EBREAK,C.EBREAK, making sure pc+4 is a valid instruction boundary
      // This is needed to resume execution from epc+4 after ebreak handling
      if(instr_name == EBREAK) begin
        asm_str = ".4byte 0x00100073 # ebreak";
      end
    end
    if(comment != "")
      asm_str = {asm_str, " #",comment};
    return asm_str.tolower();
  endfunction

  function bit [6:0] get_opcode();
    case (instr_name) inside
      LUI                                                          : get_opcode = 7'b0110111;
      AUIPC                                                        : get_opcode = 7'b0010111;
      JAL                                                          : get_opcode = 7'b1101111;
      JALR                                                         : get_opcode = 7'b1100111;
      BEQ, BNE, BLT, BGE, BLTU, BGEU                               : get_opcode = 7'b1100011;
      LB, LH, LW, LBU, LHU, LWU, LD                                : get_opcode = 7'b0000011;
      SB, SH, SW, SD                                               : get_opcode = 7'b0100011;
      ADDI, SLTI, SLTIU, XORI, ORI, ANDI, SLLI, SRLI, SRAI, NOP    : get_opcode = 7'b0010011;
      ADD, SUB, SLL, SLT, SLTU, XOR, SRL, SRA, OR, AND, MUL,
      MULH, MULHSU, MULHU, DIV, DIVU, REM, REMU                    : get_opcode = 7'b0110011;
      ADDIW, SLLIW, SRLIW, SRAIW                                   : get_opcode = 7'b0011011;
      MULH, MULHSU, MULHU, DIV, DIVU, REM, REMU                    : get_opcode = 7'b0110011;
      FENCE, FENCE_I                                               : get_opcode = 7'b0001111;
      ECALL, EBREAK                                                : get_opcode = 7'b1110011;
      ADDW, SUBW, SLLW, SRLW, SRAW, MULW, DIVW, DIVUW, REMW, REMUW : get_opcode = 7'b0111011;
      ECALL, EBREAK, URET, SRET, MRET, DRET, WFI, SFENCE_VMA       : get_opcode = 7'b1110011;
      default : `uvm_fatal(`gfn, $sformatf("Unsupported instruction %0s", instr_name.name()))
    endcase
  endfunction

  virtual function bit [2:0] get_func3();
    case (instr_name) inside
      JALR       : get_func3 = 3'b000;
      BEQ        : get_func3 = 3'b000;
      BNE        : get_func3 = 3'b001;
      BLT        : get_func3 = 3'b100;
      BGE        : get_func3 = 3'b101;
      BLTU       : get_func3 = 3'b110;
      BGEU       : get_func3 = 3'b111;
      LB         : get_func3 = 3'b000;
      LH         : get_func3 = 3'b001;
      LW         : get_func3 = 3'b010;
      LBU        : get_func3 = 3'b100;
      LHU        : get_func3 = 3'b101;
      SB         : get_func3 = 3'b000;
      SH         : get_func3 = 3'b001;
      SW         : get_func3 = 3'b010;
      ADDI       : get_func3 = 3'b000;
      NOP        : get_func3 = 3'b000;
      SLTI       : get_func3 = 3'b010;
      SLTIU      : get_func3 = 3'b011;
      XORI       : get_func3 = 3'b100;
      ORI        : get_func3 = 3'b110;
      ANDI       : get_func3 = 3'b111;
      SLLI       : get_func3 = 3'b001;
      SRLI       : get_func3 = 3'b101;
      SRAI       : get_func3 = 3'b101;
      ADD        : get_func3 = 3'b000;
      SUB        : get_func3 = 3'b000;
      SLL        : get_func3 = 3'b001;
      SLT        : get_func3 = 3'b010;
      SLTU       : get_func3 = 3'b011;
      XOR        : get_func3 = 3'b100;
      SRL        : get_func3 = 3'b101;
      SRA        : get_func3 = 3'b101;
      OR         : get_func3 = 3'b110;
      AND        : get_func3 = 3'b111;
      FENCE      : get_func3 = 3'b000;
      FENCE_I    : get_func3 = 3'b001;
      ECALL      : get_func3 = 3'b000;
      EBREAK     : get_func3 = 3'b000;
      LWU        : get_func3 = 3'b110;
      LD         : get_func3 = 3'b011;
      SD         : get_func3 = 3'b011;
      ADDIW      : get_func3 = 3'b000;
      SLLIW      : get_func3 = 3'b001;
      SRLIW      : get_func3 = 3'b101;
      SRAIW      : get_func3 = 3'b101;
      ADDW       : get_func3 = 3'b000;
      SUBW       : get_func3 = 3'b000;
      SLLW       : get_func3 = 3'b001;
      SRLW       : get_func3 = 3'b101;
      SRAW       : get_func3 = 3'b101;
      MUL        : get_func3 = 3'b000;
      MULH       : get_func3 = 3'b001;
      MULHSU     : get_func3 = 3'b010;
      MULHU      : get_func3 = 3'b011;
      DIV        : get_func3 = 3'b100;
      DIVU       : get_func3 = 3'b101;
      REM        : get_func3 = 3'b110;
      REMU       : get_func3 = 3'b111;
      MULW       : get_func3 = 3'b000;
      DIVW       : get_func3 = 3'b100;
      DIVUW      : get_func3 = 3'b101;
      REMW       : get_func3 = 3'b110;
      REMUW      : get_func3 = 3'b111;
      ECALL, EBREAK, URET, SRET, MRET, DRET, WFI, SFENCE_VMA : get_func3 = 3'b000;
      default : `uvm_fatal(`gfn, $sformatf("Unsupported instruction %0s", instr_name.name()))
    endcase
  endfunction

  function bit [6:0] get_func7();
    case (instr_name)
      SLLI   : get_func7 = 7'b0000000;
      SRLI   : get_func7 = 7'b0000000;
      SRAI   : get_func7 = 7'b0100000;
      ADD    : get_func7 = 7'b0000000;
      SUB    : get_func7 = 7'b0100000;
      SLL    : get_func7 = 7'b0000000;
      SLT    : get_func7 = 7'b0000000;
      SLTU   : get_func7 = 7'b0000000;
      XOR    : get_func7 = 7'b0000000;
      SRL    : get_func7 = 7'b0000000;
      SRA    : get_func7 = 7'b0100000;
      OR     : get_func7 = 7'b0000000;
      AND    : get_func7 = 7'b0000000;
      FENCE  : get_func7 = 7'b0000000;
      FENCE_I : get_func7 = 7'b0000000;
      SLLIW  : get_func7 = 7'b0000000;
      SRLIW  : get_func7 = 7'b0000000;
      SRAIW  : get_func7 = 7'b0100000;
      ADDW   : get_func7 = 7'b0000000;
      SUBW   : get_func7 = 7'b0100000;
      SLLW   : get_func7 = 7'b0000000;
      SRLW   : get_func7 = 7'b0000000;
      SRAW   : get_func7 = 7'b0100000;
      MUL    : get_func7 = 7'b0000001;
      MULH   : get_func7 = 7'b0000001;
      MULHSU : get_func7 = 7'b0000001;
      MULHU  : get_func7 = 7'b0000001;
      DIV    : get_func7 = 7'b0000001;
      DIVU   : get_func7 = 7'b0000001;
      REM    : get_func7 = 7'b0000001;
      REMU   : get_func7 = 7'b0000001;
      MULW   : get_func7 = 7'b0000001;
      DIVW   : get_func7 = 7'b0000001;
      DIVUW  : get_func7 = 7'b0000001;
      REMW   : get_func7 = 7'b0000001;
      REMUW  : get_func7 = 7'b0000001;
      ECALL  : get_func7 = 7'b0000000;
      EBREAK : get_func7 = 7'b0000000;
      URET   : get_func7 = 7'b0000000;
      SRET   : get_func7 = 7'b0001000;
      MRET   : get_func7 = 7'b0011000;
      DRET   : get_func7 = 7'b0111101;
      WFI    : get_func7 = 7'b0001000;
      SFENCE_VMA: get_func7 = 7'b0001001;
      default : `uvm_fatal(`gfn, $sformatf("Unsupported instruction %0s", instr_name.name()))
    endcase
  endfunction

  // Convert the instruction to assembly code
  virtual function string convert2bin(string prefix = "");
    string binary;
    case(format)
      J_FORMAT: begin
          binary = $sformatf("%8h", {imm[20], imm[10:1], imm[11], imm[19:12], rd,  get_opcode()});
      end
      U_FORMAT: begin
          binary = $sformatf("%8h", {imm[31:12], rd,  get_opcode()});
      end
      I_FORMAT: begin
        if(instr_name inside {FENCE, FENCE_I})
          binary = $sformatf("%8h", {17'b0, get_func3(), 5'b0, get_opcode()});
        else if(instr_name == ECALL)
          binary = $sformatf("%8h", {get_func7(), 18'b0, get_opcode()});
        else if(instr_name inside {URET, SRET, MRET})
          binary = $sformatf("%8h", {get_func7(), 5'b00010, 13'b0, get_opcode()});
        else if(instr_name inside {DRET})
          binary = $sformatf("%8h", {get_func7(), 5'b10010, 13'b0, get_opcode()});
        else if(instr_name == EBREAK)
          binary = $sformatf("%8h", {get_func7(), 5'd1, 13'b0, get_opcode()});
        else if(instr_name == WFI)
          binary = $sformatf("%8h", {get_func7(), 5'b00101, 13'b0, get_opcode()});
        else
          binary = $sformatf("%8h", {imm[11:0], rs1, get_func3(), rd, get_opcode()});
      end
      S_FORMAT: begin
          binary = $sformatf("%8h", {imm[11:5], rs2, rs1, get_func3(), imm[4:0], get_opcode()});
      end
      B_FORMAT: begin
          binary = $sformatf("%8h",
                             {imm[12], imm[10:5], rs2, rs1, get_func3(),
                              imm[4:1], imm[11], get_opcode()});
      end
      R_FORMAT: begin
        if(instr_name == SFENCE_VMA)
          binary = $sformatf("%8h", {get_func7(), 18'b0, get_opcode()});
        else
          binary = $sformatf("%8h", {get_func7(), rs2, rs1, get_func3(), rd, get_opcode()});
      end
      default: `uvm_fatal(`gfn, $sformatf("Unsupported format %0s", format.name()))
    endcase
    return {prefix, binary};
  endfunction

  virtual function string get_instr_name();
    get_instr_name = instr_name.name();
    foreach(get_instr_name[i]) begin
      if (get_instr_name[i] == "_") begin
        get_instr_name[i] = ".";
      end
    end
    return get_instr_name;
  endfunction

  // Get RVC register name for CIW, CL, CS, CB format
  function bit [2:0] get_c_gpr(riscv_reg_t gpr);
    return gpr[2:0];
  endfunction

  // Default return imm value directly, can be overriden to use labels and symbols
  // Example: %hi(symbol), %pc_rel(label) ...
  virtual function string get_imm();
    return imm_str;
  endfunction

  virtual function void clear_unused_label();
    if(has_label && !is_branch_target && is_local_numeric_label) begin
      has_label = 1'b0;
    end
  endfunction

  virtual function void do_copy(uvm_object rhs);
    riscv_instr rhs_;
    super.copy(rhs);
    assert($cast(rhs_, rhs));
    this.group          = rhs_.group;
    this.format         = rhs_.format;
    this.category       = rhs_.category;
    this.instr_name     = rhs_.instr_name;
    this.rs2            = rhs_.rs2;
    this.rs1            = rhs_.rs1;
    this.rd             = rhs_.rd;
    this.imm            = rhs_.imm;
    this.imm_type       = rhs_.imm_type;
    this.imm_len        = rhs_.imm_len;
    this.imm_mask       = rhs_.imm_mask;
    this.imm_str        = rhs_.imm_str;
    this.imm_mask       = rhs_.imm_mask;
    this.is_compressed  = rhs_.is_compressed;
    this.has_rs2        = rhs_.has_rs2;
    this.has_rs1        = rhs_.has_rs1;
    this.has_rd         = rhs_.has_rd;
    this.has_imm        = rhs_.has_imm;
  endfunction : do_copy

  virtual function void update_imm_str();
    imm_str = $sformatf("%0d", $signed(imm));
  endfunction

  `include "isa/riscv_instr_cov.svh"

endclass
