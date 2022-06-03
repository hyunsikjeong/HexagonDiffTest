#include <stdio.h>
#include <unistd.h>
#include <sys/mman.h>

int main()
{
    // Only used in quic/qemu
    int *ptr = (int*) mmap((void *)0x4100000, 65536, PROT_READ | PROT_WRITE, MAP_FIXED | MAP_PRIVATE | MAP_ANON, -1, 0);
    // Only used in hexagon-sim
    unsigned int mem_sim[4] = {0};

    unsigned int *mem = (unsigned int*) 0x410eee0;
    int i;
    unsigned int inputs[21] = {};
    read(0, inputs, sizeof(inputs));
    for (i = 0; i < 10; i++) {
        printf("R%d: %u\n", i, inputs[i]);
    }
    printf("C4: %u\n", inputs[10]);
    printf("C6: %u\n", inputs[11]);
    printf("C7: %u\n", inputs[12]);
    printf("C8: %u\n", inputs[13]);
    printf("C11: %u\n", inputs[14]);
    printf("C12: %u\n", inputs[15]);
    printf("C13: %u\n", inputs[16]);
    for (i = 0; i < 4; i++) {
        mem[i] = inputs[17 + i];
        printf("inputs: %u\n", inputs[17 + i]);
        printf("Mem%d: %u\n", i, mem[i]);
    }
    __asm(
        "{"
        "R10 = %0;"
        "} {"
        "R0 = memw(R10 + #0);"
        "R1 = memw(R10 + #4);"
        "} {"
        "R2 = memw(R10 + #8);"
        "R3 = memw(R10 + #12);"
        "} {"
        "R4 = memw(R10 + #16);"
        "R5 = memw(R10 + #20);"
        "} {"
        "R6 = memw(R10 + #24);"
        "R7 = memw(R10 + #28);"
        "} {"
        "R8 = memw(R10 + #32);"
        "R9 = memw(R10 + #36);"
        "} {"
        "R11 = memw(R10 + #40);"
        "R12 = memw(R10 + #44);"
        "} {"
        "R13 = memw(R10 + #48);"
        "R14 = memw(R10 + #52);"
        "} {"
        "R15 = memw(R10 + #56);"
        "R16 = memw(R10 + #60);"
        "} {"
        "R17 = memw(R10 + #64);"
        "} {"
        "C4 = R11;"
        "} {"
        "C6 = R12;"
        "} {"
        "C7 = R13;"
        "} {"
        "C8 = R14;"
        "} {"
        "R20 = C11;"
        "} {"
        "C11 = R15;"
        "} {"
        "C12 = R16;"
        "} {"
        "C13 = R17;"
        "} {"
        " nop; nop; nop; nop; "
        "} {"
        "R11 = C4;"
        "} {"
        "R12 = C6;"
        "} {"
        "R13 = C7;"
        "} {"
        "R14 = C8;"
        "} {"
        "R15 = C11;"
        "} {"
        "R16 = C12;"
        "} {"
        "R17 = C13;"
        "} {"
        "C11 = R20;"
        "} {"
        "memw(R10 + #40) = R11;"
        "memw(R10 + #44) = R12;"
        "} {"
        "memw(R10 + #48) = R13;"
        "memw(R10 + #52) = R14;"
        "} {"
        "memw(R10 + #56) = R15;"
        "memw(R10 + #60) = R16;"
        "} {"
        "memw(R10 + #64) = R17;"
        "} {"
        "memw(R10 + #0) = R0;"
        "memw(R10 + #4) = R1;"
        "} {"
        "memw(R10 + #8) = R2;"
        "memw(R10 + #12) = R3;"
        "} {"
        "memw(R10 + #16) = R4;"
        "memw(R10 + #20) = R5;"
        "} {"
        "memw(R10 + #24) = R6;"
        "memw(R10 + #28) = R7;"
        "} {"
        "memw(R10 + #32) = R8;"
        "memw(R10 + #36) = R9;"
        "}"
    : : "r" (inputs));
    for (i = 0; i < 10; i++) {
        printf("R%d: %u\n", i, inputs[i]);
    }
    printf("C4: %u\n", inputs[10]);
    printf("C6: %u\n", inputs[11]);
    printf("C7: %u\n", inputs[12]);
    printf("C8: %u\n", inputs[13]);
    printf("C11: %u\n", inputs[14]);
    printf("C12: %u\n", inputs[15]);
    printf("C13: %u\n", inputs[16]);
    for (i = 0; i < 4; i++) {
        printf("Mem%d: %u\n", i, mem[i]);
    }
}
