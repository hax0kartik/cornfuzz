#include <vector>
#include <string>
#include <tuple>
#include <unordered_set>
#include <unicorn/unicorn.h>

class Emulator{
    public:
    void WriteMemory(std::vector<uint8_t> data, uint32_t address);
    std::vector<uint8_t> ReadMemory(uint32_t address, size_t size);
    void AddCodeCallback(void *callback);
    void MapAndWriteRegion(std::vector<uint8_t> data, uint32_t address, std::string region_name);
    void MapHeap(uint32_t address, size_t size);
    uint32_t malloc(size_t size);
    bool UpdateCoverage();
    size_t GetCoverage();
    void EnableCoverage();
    
    virtual std::string DumpRegs(){ return "Dumping regs"; };
    virtual void Init() = 0;
    virtual void InitStack(uint32_t base, uint32_t size) = 0;
    virtual void push_uint32t(uint32_t value) = 0;
    virtual uint32_t pop_uint32t() = 0;
    virtual void CallFunc(uint32_t addr, std::vector<uint32_t> list = std::vector<uint32_t>(4)) = 0;
    virtual uint32_t GetReturnValue() = 0;
    virtual uint32_t GetPCValue() = 0;

    protected:
    void UniErr(const uc_err err);
    uint32_t heap_next_addr(size_t size);
    //void hook_code(uc_engine *uc, uint64_t address, uint32_t size, void *user_data);
    uc_engine *uc_handle;

    private:
    uint32_t heap_addr = 0x0;
    uint32_t heap_align = 0x1000;
    uint32_t heap_size = 32;
    uint32_t heap_mask = (1 << heap_size) - 1;
    std::vector<std::tuple<std::string, uint32_t, uint32_t>> regions;
    std::vector<uc_hook> callbacks;
    std::unordered_set<uint32_t> coveredPCs;
};