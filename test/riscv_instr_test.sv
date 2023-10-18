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

// Sanity test for riscv_instr_test class
class riscv_instr_test extends riscv_instr_base_test;

  `uvm_component_utils(riscv_instr_test)
  `uvm_component_new

  task run_phase(uvm_phase phase);
    int fd;
    riscv_instr instr;
    riscv_instr_name_t instr_name;
    string test_name = $sformatf("%0s_0.S", asm_file_name);
    fd = $fopen(test_name,"w");
    `uvm_info(`gfn, "Creating instruction list", UVM_LOW)
    riscv_instr::create_instr_list(cfg);                                            //  形成可产生的指令列表（哪些指令能被随机到）
    riscv_csr_instr::create_csr_filter(cfg);                                        //  形成csr列表（哪些csr能被随机到）
    `uvm_info(`gfn, "Randomizing instruction list now...", UVM_LOW)
    repeat (10000) begin
      instr = riscv_instr::get_rand_instr();                                        //  产生一个随机指令
      `DV_CHECK_RANDOMIZE_FATAL(instr);                                             //  利用instr的pre post randomize 和 constrain 生成：rs rd imm 
      $fwrite(fd, {instr.convert2asm(),"\n"});                                       
    end
    repeat (10000) begin
      instr = riscv_instr::get_rand_instr(.include_category({LOAD, STORE}));        //  传参，产生一个LOAD / STORE 随机指令
      `DV_CHECK_RANDOMIZE_FATAL(instr);                                             //  利用instr的pre post randomize 和 constrain 生成：rs rd imm 
      $fwrite(fd, {instr.convert2asm(),"\n"});                                      //  转换成汇编指令写入文件 
    end 
    repeat (10000) begin
      instr = riscv_instr::get_rand_instr(.exclude_category({LOAD, STORE , BRANCH}),//  传参，产生一个LOAD / STORE / BRANCH 随机指令  group是 RV32I / RV32M
                                          .include_group({RV32I, RV32M}));
      `DV_CHECK_RANDOMIZE_FATAL(instr);                                             //  利用instr的pre post randomize 和 constrain 生成：rs rd imm 
      $fwrite(fd, {instr.convert2asm(),"\n"});                                      //  转换成汇编指令写入文件 
    end
    $fclose(fd);                                                                    //  关闭文件
    `uvm_info(get_full_name(), $sformatf("%0s is generated", test_name), UVM_LOW)   //  打印消息 
  endtask

  virtual function void randomize_cfg();                //  和base中的是一样的，不太清楚为什么在extend之后再写一次。 对cfg进行随机
    `DV_CHECK_RANDOMIZE_FATAL(cfg);
    `uvm_info(`gfn, $sformatf("riscv_instr_gen_config is randomized:\n%0s",
                    cfg.sprint()), UVM_LOW)
  endfunction

endclass
