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

// Base class for RISC-V instruction stream
// A instruction stream here is a  queue of RISC-V basic instructions.
// This class also provides some functions to manipulate the instruction stream, like insert a new
// instruction, mix two instruction streams etc.
// RISC-V指令流的基础类
// 这个基础类还提供了一些操作指令流的方法，比如插入新的指令，混合两个指令流等。
class riscv_instr_stream extends uvm_object;

  riscv_instr           instr_list[$];   // 动态数组，用于存储指令流中的指令
  int unsigned          instr_cnt;       // 无符号整数，表示指令流中指令的数量
  string                label = "";      // 标签
  // User can specify a small group of available registers to generate various hazard condition
  rand riscv_reg_t      avail_regs[];     // 指定一组可用的寄存器，以生成不同的冒险条件，指令执行过程中可能出现的竞争或冲突条件，比如写后读（RAW）、读后写（WAR）和写后写（WAW）等冒险
  // Some additional reserved registers that should not be used as rd register
  // by this instruction stream
  riscv_reg_t           reserved_rd[];    // 包含一些额外的保留寄存器，这些寄存器不应作为指令流的rd寄存器使用
  int                   hart;             // 线程，核的编号 

  `uvm_object_utils(riscv_instr_stream)   // 可以使用打印、比较、复制等
  `uvm_object_new                         // 创建riscv_instr_stream类的新实例

  // Initialize the instruction stream, create each instruction instance    用于初始化指令流并创建每个指令实例
  function void initialize_instr_list(int unsigned instr_cnt);
    instr_list = {};
    this.instr_cnt = instr_cnt;     // initial 并且传入指令的数量
    create_instr_instance();
  endfunction

  virtual function void create_instr_instance();
    riscv_instr instr;             // 创建指令，并添在list末尾
    for(int i = 0; i < instr_cnt; i++) begin
      instr = riscv_instr::type_id::create($sformatf("instr_%0d", i));
      instr_list.push_back(instr);
    end
  endfunction

  // Insert an instruction to the existing instruction stream at the given index
  // When index is -1, the instruction is injected at a random location  // 用于将给定的指令instr插入到现有的指令流instr_list中的指定索引idx处。
  // 函数接受两个参数，instr是要插入的指令实例，idx是要插入的位置索引。如果idx的值为-1，那么指令将被注入到一个随机位置。
  function void insert_instr(riscv_instr instr, int idx = -1);
    int current_instr_cnt = instr_list.size();     // 获取list的size
    if (current_instr_cnt == 0) begin
      idx = 0;
    end else if (idx == -1) begin
      idx = $urandom_range(0, current_instr_cnt-1);
      while(instr_list[idx].atomic) begin // 是否是原子指令
       idx += 1;
       if (idx == current_instr_cnt - 1) begin
         instr_list = {instr_list, instr};
         return;
       end
      end
    end else if((idx > current_instr_cnt) || (idx < 0)) begin
      `uvm_error(`gfn, $sformatf("Cannot insert instr:%0s at idx %0d",
                       instr.convert2asm(), idx))
    end
    instr_list.insert(idx, instr);
  endfunction

  // Insert an instruction to the existing instruction stream at the given index
  // When index is -1, the instruction is injected at a random location
  // When replace is 1, the original instruction at the inserted position will be replaced
  // 把一串的指令流插入当前指令流中
  function void _stream(riscv_instr new_instr[], int idx = -1, bit replace = 1'b0);
    int current_instr_cnt = instr_list.size();
    int new_instr_cnt = new_instr.size();
    if(current_instr_cnt == 0) begin
      instr_list = new_instr;
      return;
    end
    if(idx == -1) begin
      idx = $urandom_range(0, current_instr_cnt-1);
      repeat(10) begin
       if (instr_list[idx].atomic) break;
       idx = $urandom_range(0, current_instr_cnt-1);
      end
      if (instr_list[idx].atomic) begin
        foreach (instr_list[i]) begin
          if (!instr_list[i].atomic) begin
            idx = i;
            break;
          end
        end
        if (instr_list[idx].atomic) begin
          `uvm_fatal(`gfn, $sformatf("Cannot inject the instruction"))
        end
      end
    end else if((idx > current_instr_cnt) || (idx < 0)) begin
      `uvm_error(`gfn, $sformatf("Cannot insert instr stream at idx %0d", idx))
    end
    // When replace is 1, the original instruction at this index will be removed. The label of the
    // original instruction will be copied to the head of inserted instruction stream.
    if(replace) begin
      new_instr[0].label = instr_list[idx].label;
      new_instr[0].has_label = instr_list[idx].has_label;
      if (idx == 0) begin
        instr_list = {new_instr, instr_list[idx+1:current_instr_cnt-1]};
      end else begin
        instr_list = {instr_list[0:idx-1], new_instr, instr_list[idx+1:current_instr_cnt-1]};
      end
    end else begin
      if (idx == 0) begin
        instr_list = {new_instr, instr_list[idx:current_instr_cnt-1]};
      end else begin
        instr_list = {instr_list[0:idx-1], new_instr, instr_list[idx:current_instr_cnt-1]};
      end
    end
  endfunction

  // Mix the input instruction stream with the original instruction, the instruction order is
  // preserved. When 'contained' is set, the original instruction stream will be inside the
  // new instruction stream with the first and last instruction from the input instruction stream.
  // 融合两个指令流
  function void mix_instr_stream(riscv_instr new_instr[], bit contained = 1'b0);
    int current_instr_cnt = instr_list.size();
    int _position[];
    int new_instr_cnt = new_instr.size();
    _position = new[new_instr_cnt];
    `DV_CHECK_STD_RANDOMIZE_WITH_FATAL(_position,
      foreach(_position[i]) {
        _position[i] inside {[0:current_instr_cnt-1]};
      })
    if (_position.size() > 0) begin
      _position.sort();
    end
    if(contained) begin
      _position[0] = 0;
      if(new_instr_cnt > 1)
        _position[new_instr_cnt-1] = current_instr_cnt-1;
    end
    foreach(new_instr[i]) begin
      (new_instr[i], insert_instr_position[i] + i);
    end
  endfunction

 function string convert2string();  // 流指令转换成 asm汇编指令
    string str;
    foreach(instr_list[i])
      str = {str, instr_list[i].convert2asm(), "\n"};
    return str;
  endfunction

endclass

// Generate a random instruction stream based on the configuration
// There are two ways to use this class to generate instruction stream
// 1. For short instruction stream, you can call randomize() directly.
// 2. For long instruction stream (>1K), randomize() all instructions together might take a long
// time for the constraint solver. In this case, you can call gen_instr to generate instructions
// one by one. The time only grows linearly with the instruction count
// 生成基于配置的随机指令流
// 对于短指令流，可以直接调用randomize()方法
// 对于长指令流（大于1K），将所有指令一起随机化可能需要很长时间，因为约束求解器需要处理大量的指令。
// 在这种情况下，可以调用gen_instr方法来逐个生成指令。这样可以降低生成指令流的时间复杂度，使其仅随指令数量的增加而线性增长
class riscv_rand_instr_stream extends riscv_instr_stream;

  riscv_instr_gen_config  cfg;                                     //  指令生成器的配置信息
  bit                     kernel_mode;                             //  是否处于内核模式
  riscv_instr_name_t      allowed_instr[$];                        //  允许生成的指令名称
  int unsigned            category_dist[riscv_instr_category_t];   //  不同指令类别的分布信息

  `uvm_object_utils(riscv_rand_instr_stream)
  `uvm_object_new

  virtual function void create_instr_instance();
    riscv_instr instr;
    for (int i = 0; i < instr_cnt; i++) begin
      instr_list.push_back(null);                     // 预先分配空间
    end
  endfunction

  virtual function void setup_allowed_instr(bit no_branch = 1'b0, bit no_load_store = 1'b1);     //   设置允许生成的指令类型
    allowed_instr = riscv_instr::basic_instr;              //   默认情况下，只能有basic_的指令        
    if (no_branch == 0) begin                              //   允许分支指令
      allowed_instr = {allowed_instr, riscv_instr::instr_category[BRANCH]};
    end
    if (no_load_store == 0) begin                          //   允许 load  store 指令
      allowed_instr = {allowed_instr, riscv_instr::instr_category[LOAD],
                                      riscv_instr::instr_category[STORE]};
    end
    setup_instruction_dist(no_branch, no_load_store);      //   设置指令的分布情况
  endfunction

  virtual function void randomize_avail_regs();           //   用于随机化avail_regs数组。avail_regs数组存储了可用的寄存器列表
    if(avail_regs.size() > 0) begin
      `DV_CHECK_STD_RANDOMIZE_WITH_FATAL(avail_regs,
                                         unique{avail_regs};
                                         avail_regs[0] inside {[S0 : A5]};
                                         foreach(avail_regs[i]) {
                                           !(avail_regs[i] inside {cfg.reserved_regs, reserved_rd});
                                         },
                                         "Cannot randomize avail_regs")
    end
  endfunction

  function void setup_instruction_dist(bit no_branch = 1'b0, bit no_load_store = 1'b1);
    if (cfg.dist_control_mode) begin  // 分布比例  均匀分布 正态分布  自定义分布
      category_dist = cfg.category_dist;
      if (no_branch) begin
        category_dist[BRANCH] = 0;
      end
      if (no_load_store) begin
        category_dist[LOAD] = 0;
        category_dist[STORE] = 0;
      end
      `uvm_info(`gfn, $sformatf("setup_instruction_dist: %0d", category_dist.size()), UVM_LOW)
    end
  endfunction

virtual function void gen_instr(bit no_branch = 1'b0, bit no_load_store = 1'b1,   // 用于生成指令序列
                                  bit is_debug_program = 1'b0);
  setup_allowed_instr(no_branch, no_load_store);  // 设置允许生成的指令类型。传递的参数为no_branch和no_load_store，用于控制是否允许生成分支指令和加载/存储指令
    foreach(instr_list[i]) begin
      randomize_instr(instr_list[i], is_debug_program);    // randomize_instr函数对指令进行, 是否是调试指令  
    end
    // Do not allow branch instruction as the last instruction because there's no
    // forward branch target      保证最后一个指令不是分支跳转指令
    while (instr_list[$].category == BRANCH) begin      // 如果最后一条指令是分支指令，则将其从instr_list中移除，并继续检查，直到最后一条指令不是分支指令或instr_list为空为止。
      void'(instr_list.pop_back());
      if (instr_list.size() == 0) break;
    end
  endfunction

  function void randomize_instr(output riscv_instr instr,   //  存储生成的指令
                                input  bit is_in_debug = 1'b0,    //  是否在调试模式下生成指令
                                input  bit disable_dist = 1'b0,   //  用于禁用指令分布控制
                                input  riscv_instr_group_t include_group[$] = {});    //  用于指定需要包含的指令组，默认为空
    riscv_instr_name_t exclude_instr[];    //   用于存储需要排除的指令
    if ((SP inside {reserved_rd, cfg.reserved_regs}) ||   //  如果堆栈指针（SP）在保留寄存器列表reserved_rd或cfg.reserved_regs中，这意味着SP寄存器被保留用于特定目的，不应该被生成的指令修改。
                                                          //  因此，需要将一些与SP相关的指令排除，以防止错误地修改SP寄存器。
        ((avail_regs.size() > 0) && !(SP inside {avail_regs}))) begin   //  其次，如果avail_regs数组不为空且SP不在avail_regs中，这意味着虽然有一些可用的寄存器，但堆栈指针（SP）不在可用寄存器列表中。
                                                          //  这可能意味着SP寄存器被用于其他目的，或者不应该被生成的指令使用。因此，需要排除一些与SP相关的指令，以确保不会错误地使用SP寄存器
      exclude_instr = {C_ADDI4SPN, C_ADDI16SP, C_LWSP, C_LDSP};    // 通过将与堆栈指针（SP）相关的指令添加到exclude_instr数组中，可以确保在随机生成指令时，不会选择这些需要排除的指令
    end
    
    // Post-process the allowed_instr and exclude_instr lists to handle    // 是否包涵 EBREAK指令
    // adding ebreak instructions to the debug rom.
    if (is_in_debug) begin
      if (cfg.no_ebreak && cfg.enable_ebreak_in_debug_rom) begin
        allowed_instr = {allowed_instr, EBREAK, C_EBREAK};
      end else if (!cfg.no_ebreak && !cfg.enable_ebreak_in_debug_rom) begin
        exclude_instr = {exclude_instr, EBREAK, C_EBREAK};
      end
    end
    
    instr = riscv_instr::get_rand_instr(.include_instr(allowed_instr),         //  **** 根据 allowed exclude  include_group  生成指令
                                        .exclude_instr(exclude_instr),
                                        .include_group(include_group));
    instr.m_cfg = cfg;               
    randomize_gpr(instr);                //  对指令的通用寄存器进行随机
  endfunction 

 function void randomize_gpr(riscv_instr instr);     // 用于指令的通用寄存器的constrain_with 随机
    `DV_CHECK_RANDOMIZE_WITH_FATAL(instr,
    if (avail_regs.size() > 0) {   // with
        if (has_rs1) {
          rs1 inside {avail_regs};
        }
        if (has_rs2) {
          rs2 inside {avail_regs};
        }
        if (has_rd) {
          rd  inside {avail_regs};
        }
      }
          foreach (reserved_rd[i]) {         //  with
        if (has_rd) {
          rd != reserved_rd[i];
        }
        if (format == CB_FORMAT) {
          rs1 != reserved_rd[i];
        }
      }
          foreach (cfg.reserved_regs[i]) {     //  with
        if (has_rd) {
          rd != cfg.reserved_regs[i];     //  确保rd寄存器的值不等于reserved_rd数组中的任何元素
        }
        if (format == CB_FORMAT) {
          rs1 != cfg.reserved_regs[i];    // 确保rd寄存器的值不等于cfg.reserved_regs数组中
        }
      }
      // TODO: Add constraint for CSR, floating point register
    )
  endfunction

  function riscv_instr get_init_gpr_instr(riscv_reg_t gpr, bit [XLEN-1:0] val);   //  随机初始化通用寄存器
    riscv_pseudo_instr li_instr;
    li_instr = riscv_pseudo_instr::type_id::create("li_instr");
    `DV_CHECK_RANDOMIZE_WITH_FATAL(li_instr,
       pseudo_instr_name == LI;
       rd == gpr;
    )
    li_instr.imm_str = $sformatf("0x%0x", val);
    return li_instr;
  endfunction

  function void add_init_vector_gpr_instr(riscv_vreg_t gpr, bit [XLEN-1:0] val);   //   随机初始化通用向量寄存器
    riscv_vector_instr instr;
    $cast(instr, riscv_instr::get_instr(VMV));
    instr.m_cfg = cfg;
    instr.avoid_reserved_vregs_c.constraint_mode(0);
    `DV_CHECK_RANDOMIZE_WITH_FATAL(instr,
      va_variant == VX;
      vd == gpr;
      rs1 == cfg.gpr[0];
    )
    instr_list.push_front(instr);
    instr_list.push_front(get_init_gpr_instr(cfg.gpr[0], val));
  endfunction

endclass
