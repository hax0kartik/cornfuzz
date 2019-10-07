#include <vector>
#include <string>
#include <fstream>
#include "arm.h"

std::vector <uint8_t> read_data(std::string filename){
    std::ifstream input(filename, std::ios::binary);
    std::vector<uint8_t> buffer(std::istreambuf_iterator<char>(input), {});
    return buffer;
}

static Emulator *emu;
EmuArm arm;

extern "C" int LLVMFuzzerInitialize(int *argc, char*** argv) {
    (void)argc;
    (void)argv;

    emu = &arm;
    emu->Init();

    //printf("[*] Mapping region(s)... \n");
    emu->MapAndWriteRegion(read_data("newslist.text.bin"), 0x00100000, ".text");
    emu->MapAndWriteRegion(read_data("newslist.rodata.bin"), 0x00192000, ".rodata");
    //printf("[*] Fixing rodata... \n");
    emu->WriteMemory(emu->ReadMemory(0x1929a0 - 0xa4, 0xf672), 0x00192000);
    emu->MapAndWriteRegion(read_data("newslist.data.bin"), 0x001a2000, ".data");

    //printf("[*] Setting stack to 0x10000000...\n");
    emu->InitStack(0x10001000, 0x10001000 - 0xFFF);
    emu->MapHeap(0x08000000, 0x01000000);

    //printf("[*] Enabling Coverage...\n");
    emu->EnableCoverage();

    //printf("[*] Calling function GetWorkBufferSize\n");
    emu->CallFunc(0x15E438); // GetWorkBufferSize
    //printf("[+] Done!\n");

   // printf("[*] Allocating space on heap for WorkBuffer and JpegStruct_s\n");
    uint32_t size = emu->GetReturnValue();
    //printf("[+] Size 0x%lx\n", size);
    uint32_t buffer_addr = emu->malloc(size);
    JpegStruct_s = emu->malloc(0x100);
    //printf("[*] Buffer addr: %lX JpegStruct addr: %lX\n", buffer_addr, JpegStruct_s);

    //printf("[*] Calling function Initialize\n");
    emu->CallFunc(0x15E018, {JpegStruct_s, buffer_addr, size}); // Initialize
    //printf("[+] Done!\n Ret Code: %ld\n", emu->GetReturnValue());

    DSTL_addr = emu->malloc(0x96000);
    DSTR_addr = emu->malloc(0x96000);
    image_p = emu->malloc(72509);

    return 0;
}

extern "C" int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {

   // printf("Size %d\n", size);
    if (size == 0) return 0;
    std::vector<uint8_t> image(data, data + size);

    //printf("[*] Writing a %ld size image at address %lX\n", size, image_p);
    emu->WriteMemory(image, image_p);
    //printf("[+] Write Memory done");
    //printf("[*] Calling function StartMpDecocderLR\n");
    emu->CallFunc(0x15E06C, {JpegStruct_s, image_p, (uint32_t)image.size(), 0});
    //emu->CallFunc(0x15E184, {JpegStruct_s, DSTL_addr, DSTR_addr, 0x96000, image_p, (uint32_t)image.size(), 640, 480, 2});
    //printf("[+] Done!\n Ret Code: %ld\n", emu->GetReturnValue());

   // printf("[*] Coverage size: %d ins!\n", emu->GetCoverage());
    return emu->GetCoverage();
}

/*
int main(){

    printf("[*] Initing... \n");
    

    std::vector<uint8_t> image = read_data("test.MPO");
    uint32_t image_p = emu->malloc(image.size());
    printf("[*] Writing a %ld size image at address %lX\n", image.size(), image_p);
    emu->WriteMemory(image, image_p);

   // printf("[*] Calling function StartMpDecocderLR\n");
    //emu->CallFunc(0x15E06C, {JpegStruct_s, image_p, image.size(), 0});
    emu->CallFunc(0x15E184, {JpegStruct_s, DSTL_addr, DSTR_addr, 0x96000, image_p, image.size(), 640, 480, 2});
    printf("[+] Done!\n Ret Code: %ld\n", emu->GetReturnValue());

    printf("[*] Coverage size: %d ins!", emu->GetCoverage());

}
*/