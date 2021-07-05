/*
 * Copyright 2018 Google LLC
 * Copyright 2021 Coverify Systems Technology
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

//-----------------------------------------------------------------------------------------
// RISC-V instruction sequence
//
// This class is used to generate a single instruction sequence for a RISC-V assembly program.
// It's used by riscv_asm_program_gen to generate the main program and all sub-programs. The
// flow is explained below:
// For main program:
// - Generate instruction sequence body.
// - Post-process the load/store/branch instructions.
// - Insert the jump instructions to its sub-programs (done by riscv_asm_program_gen).
// For sub program:
// - Generate the stack push instructions which are executed when entering this program.
// - Generate instruction sequence body.
// - Generate the stack pop instructions which are executed before exiting this program.
// - Post-process the load/store/branch instructions.
// - Insert the jump instructions to its sub-programs (done by riscv_asm_program_gen).
// - Generate a return instruction at the end of the program.
//-----------------------------------------------------------------------------------------
module riscv.gen.riscv_instr_sequence;

import riscv.gen.riscv_instr_pkg: riscv_instr_category_t, riscv_instr_name_t,
  format_string, riscv_reg_t, indent, LABEL_STR_LEN;
import riscv.gen.riscv_core_setting: support_pmp, XLEN;

import riscv.gen.riscv_instr_gen_config: riscv_instr_gen_config;
import riscv.gen.riscv_directed_instr_lib: riscv_push_stack_instr, riscv_pop_stack_instr,
  riscv_jump_instr;
import riscv.gen.riscv_instr_stream: riscv_instr_stream, riscv_rand_instr_stream;
import riscv.gen.riscv_illegal_instr: riscv_illegal_instr;

import std.format: format;
import std.algorithm.searching: canFind;
import std.random: randomShuffle;

import esdl.base.core: urandom, getRandGen;
import esdl.data.queue: Queue;
import esdl.rand: randomize, randomize_with;


import uvm;


class riscv_instr_sequence :  uvm_sequence!(uvm_sequence_item,uvm_sequence_item)
{

  uint                     instr_cnt;            // Instruction count of this sequence
  riscv_push_stack_instr   instr_stack_enter;    // Stack push instructions for sub-programs
  riscv_pop_stack_instr    instr_stack_exit;     // Stack pop instructions for sub-programs
  riscv_rand_instr_stream  instr_stream;         // Main instruction streams
  bool                     is_main_program;      // Type of this sequence (main or sub program)
  bool                     is_debug_program;     // Indicates whether sequence is debug program
  string                   label_name;           // Label of the sequence (program name)
  riscv_instr_gen_config   cfg;                  // Configuration class handle
  Queue!string             instr_string_list; // Save the instruction list in string format
  int                      program_stack_len;    // Stack space allocated for this program
  riscv_instr_stream[]     directed_instr;     // List of all directed instruction stream
  riscv_illegal_instr      illegal_instr;        // Illegal instruction generator
  int                      illegal_instr_pct;    // Percentage of illegal instruction
  int                      hint_instr_pct;       // Percentage of HINT instruction

  mixin uvm_object_utils;
 
  this(string name = "") {
    super(name);
    if(!uvm_config_db!(riscv_instr_gen_config).get(null, "*", "instr_cfg", cfg))
      uvm_fatal(get_full_name(), "Cannot get instr_gen_cfg");
    instr_stream = riscv_rand_instr_stream.type_id.create("instr_stream");
    instr_stack_enter = riscv_push_stack_instr.type_id.create("instr_stack_enter");
    instr_stack_exit  = riscv_pop_stack_instr.type_id.create("instr_stack_exit");
    illegal_instr = riscv_illegal_instr.type_id.create("illegal_instr");
  }

  // Main function to generate the instruction stream
  // The main random instruction stream is generated by instr_stream.gen_instr(), which generates
  // each instruction one by one with a separate randomization call. It's not done by a single
  // randomization call for the entire instruction stream because this solution won't scale if
  // we have hundreds of thousands of instructions to generate. The constraint solver slows down
  // considerably as the instruction stream becomes longer. The downside is we cannot specify
  // constraints between instructions. The way to solve it is to have a dedicated directed
  // instruction stream for such scenarios, like hazard sequence.
  void gen_instr(bool is_main_program, bool no_branch = false) {
    this.is_main_program = is_main_program;
    instr_stream.cfg = cfg;
    instr_stream.initialize_instr_list(instr_cnt);
    uvm_info(get_full_name(), format("Start generating %0d instruction",
				     instr_stream.instr_list.length), UVM_LOW);
    // Do not generate load/store instruction here
    // The load/store instruction will be inserted as directed instruction stream
    instr_stream.gen_instr(no_branch, true,
                           is_debug_program);
    if(!is_main_program) {
      gen_stack_enter_instr();
      gen_stack_exit_instr();
    }
    uvm_info(get_full_name(), "Finishing instruction generation", UVM_LOW);
  }

  // Generate the stack push operations for this program
  // It pushes the necessary context to the stack like RA, T0,loop registers etc. The stack
  // pointer(SP) is reduced by the amount the stack space allocated to this program.
  void gen_stack_enter_instr() {
    bool allow_branch = ((illegal_instr_pct > 0) || (hint_instr_pct > 0)) ? false : true;
    allow_branch &= !cfg.no_branch_jump;
    // DV_CHECK_STD_RANDOMIZE_WITH_FATAL(program_stack_len,
    // Keep stack len word aligned to avoid unaligned load/store
    // program_stack_len % (XLEN/8) == 0;,
    // "Cannot randomize program_stack_len")
    program_stack_len =
      (XLEN/8) * (cast(int) urandom(cfg.min_stack_len_per_program/(XLEN/8),
				    cfg.max_stack_len_per_program/(XLEN/8) + 1));
    instr_stack_enter.cfg = cfg;
    instr_stack_enter.push_start_label = label_name ~ "_stack_p";
    instr_stack_enter.gen_push_stack_instr(program_stack_len, allow_branch);
    instr_stream.instr_list = instr_stack_enter.instr_list ~ instr_stream.instr_list;
  }

  // Recover the saved GPR from the stack
  // Advance the stack pointer(SP) to release the allocated stack space.
  void gen_stack_exit_instr() {
    instr_stack_exit.cfg = cfg;
    instr_stack_exit.gen_pop_stack_instr(program_stack_len, instr_stack_enter.saved_regs);
    instr_stream.instr_list ~= instr_stack_exit.instr_list;
  }

  //----------------------------------------------------------------------------------------------
  // Instruction post-process
  //
  // Post-process is required for branch instructions:
  //
  // - Need to assign a valid branch target. This is done by picking a random instruction label in
  //   this sequence and assigning to the branch instruction. All the non-atomic instructions
  //   will have a unique numeric label as the local branch target identifier.
  // - The atomic instruction streams don't have labels except for the first instruction. This is
  //   to avoid branching into an atomic instruction stream which breaks its atomicy. The
  //   definition of an atomic instruction stream here is a sequence of instructions which must be
  //   executed in-order.
  // - In this sequence, only forward branch is handled. The backward branch target is implemented
  //   in a dedicated loop instruction sequence. Randomly choosing a backward branch target could
  //   lead to dead loops in the absence of proper loop exiting conditions.
  //
  //----------------------------------------------------------------------------------------------
  void post_process_instr() {
    // int i;
    int label_idx;
    int branch_cnt;
    uint[]  branch_idx;
    int[int] branch_target;   // '{default: 0};
    // Insert directed instructions, it's randomly mixed with the random instruction stream.
    foreach (instr; directed_instr) {
      instr_stream.insert_instr_stream(instr.instr_list);
    }
    // Assign an index for all instructions, these indexes won't change even a new instruction
    // is injected in the post process.
    foreach (i, instr; instr_stream.instr_list) {
      instr.idx = label_idx;
      if (instr.has_label && !instr_stream.instr_list[i].atomic) {
        if ((illegal_instr_pct > 0) && (instr.is_illegal_instr == false)) {
          // The illegal instruction generator always increase PC by 4 when resume execution, need
          // to make sure PC + 4 is at the correct instruction boundary.
          if (instr.is_compressed) {
            if (i < instr_stream.instr_list.length-1) {
              if (instr_stream.instr_list[i+1].is_compressed) {
                instr.is_illegal_instr = (urandom(0, 100) < illegal_instr_pct);
              }
            }
          }
	  else {
            instr.is_illegal_instr = (urandom(0, 100) < illegal_instr_pct);
          }
        }
        if ((hint_instr_pct > 0) && (instr.is_illegal_instr == 0)) {
          if (instr.is_compressed) {
            instr.is_hint_instr = (urandom(0, 100) < hint_instr_pct);
          }
        }
        instr.label = format("%0d", label_idx);
        instr.is_local_numeric_label = true;
        label_idx++;
      }
    }
    // Generate branch target
    branch_idx.length = 30;
    //    `DV_CHECK_STD_RANDOMIZE_WITH_FATAL(,
    foreach (ref idx; branch_idx) {
      idx = urandom(1, cfg.max_branch_step+1);
    }

    foreach (i, instr; instr_stream.instr_list) {
      if ((instr.category == riscv_instr_category_t.BRANCH) &&
	 (!instr.branch_assigned) &&
	 (!instr.is_illegal_instr)) {
        // Post process the branch instructions to give a valid local label
        // Here we only allow forward branch to avoid unexpected infinite loop
        // The loop structure will be inserted with a separate routine using
        // reserved loop registers
        int branch_target_label;
        int branch_byte_offset;
        branch_target_label = instr.idx + branch_idx[branch_cnt];
        if (branch_target_label >= label_idx) {
          branch_target_label = label_idx-1;
        }
        branch_cnt++;
        if (branch_cnt == branch_idx.length) {
          branch_cnt = 0;
          branch_idx.randomShuffle(getRandGen());
        }
        uvm_info(get_full_name(),
		 format("Processing branch instruction[%0d]:%0s # %0d -> %0d",
			i, instr.convert2asm(),
			instr.idx, branch_target_label), UVM_HIGH);
        instr.imm_str = format("%0df", branch_target_label);
        // Below calculation is only needed for generating the instruction stream in binary format
        for (size_t j = i + 1; j < instr_stream.instr_list.length; j++) {
          branch_byte_offset = (instr_stream.instr_list[j-1].is_compressed) ?
	    branch_byte_offset + 2 : branch_byte_offset + 4;
          if (instr_stream.instr_list[j].label == format("%0d", branch_target_label)) {
            instr.imm = branch_byte_offset;
            break;
          }
	  else if (j == instr_stream.instr_list.length - 1) {
	    uvm_fatal(get_full_name(), format("Cannot find target label : %0d", branch_target_label));
          }
        }
        instr.branch_assigned = true;
        branch_target[branch_target_label] = 1;
      }
      // Remove the local label which is not used as branch target
      if (instr.has_label &&
	  instr.is_local_numeric_label) {
	import std.conv: to;
        int idx = instr.label.to!int();
        if (idx !in branch_target || ! branch_target[idx]) { // emulate SV {default: 0}
          instr.has_label = false;
        }
      }
      // i++;
    }
    uvm_info(get_full_name(), "Finished post-processing instructions", UVM_HIGH);
  }

  // Inject a jump instruction stream
  // This function is called by riscv_asm_program_gen with the target program label
  // The jump routine is implmented with an atomic instruction stream(riscv_jump_instr). Similar
  // to load/store instructions, JALR/JAL instructions also need a proper base address and offset
  // as the jump target.
  void insert_jump_instr(string target_label, int idx) {
    riscv_jump_instr jump_instr;
    jump_instr = riscv_jump_instr.type_id.create("jump_instr");
    jump_instr.target_program_label = target_label;
    if(!is_main_program)
      jump_instr.stack_exit_instr = instr_stack_exit.pop_stack_instr;
    jump_instr.cfg = cfg;
    jump_instr.label = label_name;
    jump_instr.idx = idx;
    jump_instr.use_jalr = is_main_program;
    jump_instr.randomize();
    instr_stream.insert_instr_stream(jump_instr.instr_list);
    uvm_info(get_full_name(), format("%0s -> %0s...done",
				     jump_instr.jump.instr_name, target_label), UVM_LOW);
  }

  // Convert the instruction stream to the string format.
  // Label is attached to the instruction if available, otherwise attach proper space to make
  // the code indent consistent.
  void generate_instr_stream(bool no_label = false) {
    string prefix, str;
    int i;
    instr_string_list = [];
    for (i = 0; i < instr_stream.instr_list.length; i++) {
      if (i == 0) {
        if (no_label) {
          prefix = format_string(" ", LABEL_STR_LEN);
	}
	else {
          prefix = format_string(format("%0s:", label_name), LABEL_STR_LEN);
	}
        instr_stream.instr_list[i].has_label = true;
      }
      else {
        if(instr_stream.instr_list[i].has_label) {
          prefix = format_string(format("%0s:", instr_stream.instr_list[i].label),
				 LABEL_STR_LEN);
        }
	else {
          prefix = format_string(" ", LABEL_STR_LEN);
        }
      }
      str = prefix ~ instr_stream.instr_list[i].convert2asm();
      instr_string_list ~= str;
    }
    // If PMP is supported, need to align <main> to a 4-byte boundary.
    // TODO(udi) - this might interfere with multi-hart programs,
    //             may need to specifically match hart0.
    if (support_pmp && !uvm_re_match(uvm_glob_to_re("*main*"), label_name)) {
      instr_string_list.pushFront(".align 2");
    }
    insert_illegal_hint_instr();
    prefix = format_string(format("%0d:", i), LABEL_STR_LEN);
    if(!is_main_program) {
      generate_return_routine(prefix);
    }
  }

  
  void generate_return_routine(string prefix) {
    import std.algorithm: countUntil;
    string str;
    int i;
    Queue!riscv_instr_name_t jump_instr = [riscv_instr_name_t.JALR];
    bool rand_lsb = cast(bool) urandom(0, 2);
    riscv_reg_t ra;
    uint ra_idx;

    auto zero_idx = cfg.reserved_regs.countUntil(riscv_reg_t.ZERO);
    
    // if (zero_idx >= 0) {
      ra_idx = urandom (0, cast(uint) cfg.reserved_regs.length-1);
      if (ra_idx <= zero_idx) ra_idx += 1;
      ra = cfg.reserved_regs[ra_idx];
    // }
    // else {
    //   ra_idx = urandom (0, cast(uint) cfg.reserved_regs.length);
    //   ra = cfg.reserved_regs[ra_idx];
    // }

    // Randomly set lsb of the return address, JALR should zero out lsb automatically
    str = prefix ~ format("addi x%0d, x%0d, %0d", ra, cfg.ra, rand_lsb);
    instr_string_list ~= str;
    if (!cfg.disable_compressed_instr) {
      jump_instr ~= riscv_instr_name_t.C_JR;
      if (!(canFind(cfg.reserved_regs, riscv_reg_t.RA))) {
        jump_instr ~= riscv_instr_name_t.C_JALR;
      }
    }
    i = urandom(0, cast(uint) jump_instr.length);
    switch (jump_instr[i]) {
    case riscv_instr_name_t.C_JALR : str = prefix ~ format("c.jalr x%0d", ra); break;
    case riscv_instr_name_t.C_JR   : str = prefix ~ format("c.jr x%0d", ra); break;
    case riscv_instr_name_t.JALR   : str = prefix ~ format("jalr x%0d, x%0d, 0", ra, ra); break;
    default: uvm_fatal(get_full_name(), format("Unsupported jump_instr %0s", jump_instr[i]));
    }
    instr_string_list ~= str;
  }

  void insert_illegal_hint_instr() {
    int bin_instr_cnt;
    int idx;
    string str;
    illegal_instr.init(cfg);
    bin_instr_cnt = instr_cnt * cfg.illegal_instr_ratio / 1000;
    if (bin_instr_cnt >= 0) {
      uvm_info(get_full_name(), format("Injecting %0d illegal instructions, ratio %0d/100",
				       bin_instr_cnt, cfg.illegal_instr_ratio), UVM_LOW);
      for(int i = 0; i != bin_instr_cnt; ++i) {
        // DV_CHECK_RANDOMIZE_WITH_FATAL(,
	illegal_instr.randomize_with! q{ exception != illegal_instr_type_e.kHintInstr;} ();
        str = indent ~ format(".4byte 0x%s # %0s",
			      illegal_instr.get_bin_str(), illegal_instr.comment);
	idx = urandom(0, cast(uint) instr_string_list.length+1);
        instr_string_list.insert(idx, str);
      }
    }
    bin_instr_cnt = instr_cnt * cfg.hint_instr_ratio / 1000;
    if (bin_instr_cnt >= 0) {
      uvm_info(get_full_name(), format("Injecting %0d HINT instructions, ratio %0d/100",
				       bin_instr_cnt, cfg.illegal_instr_ratio), UVM_LOW);
      for(int i = 0; i != bin_instr_cnt; ++i) {
	//DV_CHECK_RANDOMIZE_WITH_FATAL(illegal_instr,
	illegal_instr.randomize_with! q{exception == illegal_instr_type_e.kHintInstr;}();
        str = indent ~ format(".2byte 0x%s # %0s",
			      illegal_instr.get_bin_str(), illegal_instr.comment);
        idx = urandom(0, cast(uint) instr_string_list.length+1);
        instr_string_list.insert(idx, str);
      }
    }
  }

}
