#include "arm.h"
#include <cstdio>

void EmuArm::Init(){
    UniErr(uc_open(UC_ARCH_ARM, UC_MODE_ARM, &this->uc_handle));
    MapAndWriteRegion(std::vector<uint8_t> (0x1000), 0xd000, ".dead");
}

void EmuArm::SetStackBase(uint32_t base){
    UniErr(uc_reg_write(this->uc_handle, UC_ARM_REG_SP, &base));
}

void EmuArm::InitStack(uint32_t base, uint32_t size){
    SetStackBase(base);
    MapAndWriteRegion(std::vector<uint8_t> (size, 0), base - size, ".stack");
}

void EmuArm::push_uint32t(uint32_t value){
    uint32_t sp = 0;
    UniErr(uc_reg_read(this->uc_handle, UC_ARM_REG_SP, &sp));
    sp -= 4;
    UniErr(uc_reg_write(this->uc_handle, UC_ARM_REG_SP, &sp));
    UniErr(uc_mem_write(this->uc_handle, sp, &value, sizeof(value))); 
}

std::string EmuArm::DumpRegs(){
    auto reg_read = [](uc_engine *uc,int reg) -> uint32_t {
        int ret  = 0;
        uc_reg_read(uc, reg, &ret);
        return ret;
    };

    std::stringstream context;
    context << " R0: " << std::hex << reg_read(this->uc_handle, UC_ARM_REG_R0);
    context << " R1: " << std::hex << reg_read(this->uc_handle, UC_ARM_REG_R1);
    context << " R2: " << std::hex << reg_read(this->uc_handle, UC_ARM_REG_R2);
    context << " R3: " << std::hex << reg_read(this->uc_handle, UC_ARM_REG_R3);
    context << " R4: " << std::hex << reg_read(this->uc_handle, UC_ARM_REG_R4);
    context << " R5: " << std::hex << reg_read(this->uc_handle, UC_ARM_REG_R5);
    context << " R6: " << std::hex << reg_read(this->uc_handle, UC_ARM_REG_R6);
    context << " R7: " << std::hex << reg_read(this->uc_handle, UC_ARM_REG_R7);
    context << " R8: " << std::hex << reg_read(this->uc_handle, UC_ARM_REG_R8);
    context << " R9: " << std::hex << reg_read(this->uc_handle, UC_ARM_REG_R9);
    context << " R10: " << std::hex << reg_read(this->uc_handle, UC_ARM_REG_R10);
    context << " R11: " << std::hex << reg_read(this->uc_handle, UC_ARM_REG_R11);
    context << " R12: " << std::hex << reg_read(this->uc_handle, UC_ARM_REG_R12);
    context << " R13: " << std::hex << reg_read(this->uc_handle, UC_ARM_REG_R13);
    context << " R14: " << std::hex << reg_read(this->uc_handle, UC_ARM_REG_R14);
    context << " R15: " << std::hex << reg_read(this->uc_handle, UC_ARM_REG_R15);

    return context.str();
}
uint32_t EmuArm::GetReturnValue(){
    int ret = 0;
    uc_reg_read(this->uc_handle, UC_ARM_REG_R0, &ret);
    return ret;
}

uint32_t EmuArm::GetPCValue(){
    uint32_t pc = 0;
    uc_reg_read(this->uc_handle, UC_ARM_REG_PC, &pc);
    return pc;
}

uint32_t EmuArm::pop_uint32t(){
    uint32_t sp = 0;
    UniErr(uc_reg_read(this->uc_handle, UC_ARM_REG_SP, &sp));
    uint32_t value = 0;
    UniErr(uc_mem_read(this->uc_handle, sp, &value, sizeof(value)));
    sp += 4;
    UniErr(uc_reg_write(this->uc_handle, UC_ARM_REG_SP, &sp));
    return value;
}

void EmuArm::CallFunc(uint32_t addr, std::vector<uint32_t> list){

    uint32_t end_addr = 0xdea0;
    uc_reg_write(this->uc_handle, UC_ARM_REG_LR, &end_addr);
    UniErr(uc_reg_write(this->uc_handle, UC_ARM_REG_R0, &list[0]));
    UniErr(uc_reg_write(this->uc_handle, UC_ARM_REG_R1, &list[1]));
    UniErr(uc_reg_write(this->uc_handle, UC_ARM_REG_R2, &list[2]));
    UniErr(uc_reg_write(this->uc_handle, UC_ARM_REG_R3, &list[3]));
    for(int i = list.size() - 1; i > 3; i--){
       // printf ("Pushing val %d on stack\n", list[i]);
        push_uint32t(list[i]);
    }

    UniErr(uc_emu_start(this->uc_handle, addr, end_addr, 0, 0));
}