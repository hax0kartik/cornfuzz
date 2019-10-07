#include <list>
#include <sstream>
#include <ios>
#include "emulator.h"

class EmuArm : public Emulator{
    public:
        void Init();
        void InitStack(uint32_t base = 0x10000000, uint32_t size = 0x1000);
        void SetStackBase(uint32_t base); 
        void push_uint32t(uint32_t value);
        uint32_t pop_uint32t();
        void CallFunc(uint32_t addr, std::vector<uint32_t> list = std::vector<uint32_t>(4));
        std::string DumpRegs();
        uint32_t GetReturnValue();
        uint32_t GetPCValue();
    private:
};