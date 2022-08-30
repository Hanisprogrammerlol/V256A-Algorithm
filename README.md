# V256A-Algorithm
V256A Algorithm made by void/hanisprogrammerlol and its purpose is for signature hash

- Using pure c++ standard library
- Fast hashing performance
- Writen with c++

# To Get Started
C++ Simple Example
```c
#include "core.hpp"

int main()
{
    //text variable must be pointer if its not pointers V256A_GenerateHash will not work
    const char* text = "test123";
    //output variables must use (char*)"" for initialization
    char* out = (char*)"";
    V256A_Init();
    V256A_Digest();
    //V256A_CalcChunks() will calculate chunks based on given ascii codes you can modify it
    //into text[0] even text[4] but i recommend use it between text[0] and text[1]
    V256A_CalcChunks(text[0]);
    V256A_GenerateHash(text, 32, 32, 512);
    //process hash must be before V256A_Sweep() and after V256A_GenerateHash() function
    V256A_ProcessHash(out);
    //V256A Sweep will sweep all data from core.h struct
    V256A_Sweep();
    std::cout << out;
}
```

Doesnt work for c only works for c++