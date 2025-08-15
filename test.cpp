#include <windows.h>
#include <iostream>
#include "MMP.h"



int main() {
    while (1) {
        if (MMP_DETECT()) {
            std::cout << "mmap detected!" << std::endl;
        }
        else {
            std::cout << "1337" << std::endl;
        }
        Sleep(1000);
    }
    return 1;
}