#include "emulator.h"


void Emulator::UniErr(const uc_err err) {
    if (err) {
        throw std::runtime_error("[-] Error :" + '\n' + std::string(uc_strerror(err)) + '\n' + DumpRegs());
    }
}

static void hook_code(uc_engine *uc, uint64_t address, uint32_t size, void *user_data){
    (void)uc;
    Emulator* emu = static_cast<Emulator*>(user_data);
    emu->UpdateCoverage();
}

static bool hook_mem_invalid(uc_engine *uc, uc_mem_type type,
        uint64_t addr, int size, int64_t value, void *user_data)
{
    switch(type) {
        default:
            printf("not ok - UC_HOOK_MEM_INVALID type: %d at 0x%lX\n", type, addr);
            return false;
        case UC_MEM_READ_UNMAPPED:
            printf("not ok - Read from invalid memory at 0x%lX\n, data size = %u\n", addr, size);
            return false;
        case UC_MEM_WRITE_UNMAPPED:
            printf("not ok - Write to invalid memory at 0x%lX, data size = %u, data value = 0x%lX\n", addr, size, value);
            return false;
        case UC_MEM_FETCH_PROT:
            printf("not ok - Fetch from non-executable memory at 0x%lX\n", addr);
            return false;
        case UC_MEM_WRITE_PROT:
            printf("not ok - Write to non-writeable memory at 0x%lX, data size = %u, data value = 0x%lX\n", addr, size, value);
            return false;
        case UC_MEM_READ_PROT:
            printf("not ok - Read from non-readable memory at 0x%lX, data size = %u\n", addr, size);
            return false;
    }
}


void Emulator::EnableCoverage(){
    AddCodeCallback((void*)hook_code);
    uc_hook mem_hook;
    uc_hook_add(this->uc_handle, &mem_hook, UC_HOOK_MEM_INVALID, (void*)hook_mem_invalid, this, 1, 0);
}

uint32_t Emulator::heap_next_addr(size_t size){
    uint32_t ret = this->heap_addr;
    auto ROUND_UP = [](uint32_t x) -> uint32_t {
        return (x + 0x1000 - 1) & (~(0x1000 - 1));
    };
    this->heap_addr = (this->heap_addr + size);
    this->heap_addr = ROUND_UP(this->heap_addr);
    return ret;
}

void Emulator::MapHeap(uint32_t address, size_t size){
    this->heap_addr = address;
    UniErr(uc_mem_map(this->uc_handle, address, size, UC_PROT_ALL));
}

uint32_t Emulator::malloc(size_t size){
    uint32_t addr = heap_next_addr(size);
    return addr;
}

void Emulator::WriteMemory(std::vector<uint8_t> data, uint32_t address){
    UniErr(uc_mem_write(this->uc_handle, address, data.data(), data.size()));
}

void Emulator::AddCodeCallback(void *callback){
    callbacks.resize(callbacks.size() + 1);
    auto code_tuple = [](std::vector<std::tuple <std::string, uint32_t, uint32_t>> vec) -> std::tuple <std::string, uint32_t, uint32_t> {
        for (auto i : vec){
            std::string region = std::get<0>(i);
            if (region.compare(".text") == 0)
                return i;
        }
        throw std::runtime_error("[-] Error. Text region not found");
        return std::make_tuple("null", 0, 0);
    };
    uc_hook_add(this->uc_handle, &callbacks[callbacks.size() - 1], UC_HOOK_CODE, callback, this, std::get<1>(code_tuple(this->regions)), std::get<2>(code_tuple(this->regions)));
}

std::vector<uint8_t> Emulator::ReadMemory(uint32_t address, size_t size){
    std::vector<uint8_t> ret (size);
    UniErr(uc_mem_read(this->uc_handle, address, ret.data(), ret.size() * sizeof(uint8_t)));
    return ret;
}

void Emulator::MapAndWriteRegion(std::vector<uint8_t> data, uint32_t address, std::string region_name){
    this->regions.push_back(std::tuple <std::string, uint32_t, uint32_t> (region_name, address, address + (sizeof(uint8_t) * data.size())));
    auto ROUND_UP = [](uint32_t x) -> uint32_t {
        return (x + 0x1000 - 1) & (~(0x1000 - 1));
    };
    UniErr(uc_mem_map(this->uc_handle, address, ROUND_UP(data.size()), UC_PROT_ALL));
    UniErr(uc_mem_write(this->uc_handle, address, data.data(), data.size()));
}

size_t Emulator::GetCoverage(){
    return this->coveredPCs.size();
}

bool Emulator::UpdateCoverage() {
    const size_t oldPCSSize = this->coveredPCs.size();
    this->coveredPCs.insert(GetPCValue());
    return this->coveredPCs.size() > oldPCSSize;
}