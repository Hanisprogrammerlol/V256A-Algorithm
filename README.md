# V256A-Algorithm
V256A Algorithm made by void/hanisprogrammerlol and its purpose is for signature hash

- Using pure c++ standard library
- Fast hashing performance
- Writen with c++

# To Get Started
- C++ Simple Example
```c
#include "core.hpp"

int main()
{
    //this is basic of V256A
    //text variable must be pointer if its not pointers V256A_GenerateHash will not work
    const char* text = "test";
    //output variables must use V256A_OUTPUTSIZE_S for simple hashing
    char* out = (char*)malloc(V256A_OUTPUTSIZE_S);
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
    free(out);
}
```
- Simplified Example
```c
#include "core.hpp"

int main()
{
    //more simplified version to create V256A hash
    const char* text = "test";
    //output variables must use V256A_OUTPUTSIZE_S for simple hashing
    char* out = (char*)malloc(V256A_OUTPUTSIZE_S);
    V256A::CreateHash(text, out, 32, 32, 512);
    std::cout << out; 
    free(out);
}
```

- Generate 2 hash at a same time Example
```c
#include "core.hpp"

int main()
{
    //generate 2 hash at a same time example
    const char* text = "test";
    //output variables must use V256A_OUTPUTSIZE_S for simple hashing
    char* out = (char*)malloc(V256A_OUTPUTSIZE_S);
    V256A::CreateHash(text, out, 32, 32, 512);
    std::cout << out << "\n\n";
    V256A::CreateHash(text, out, 16, 16, 256);
    std::cout << out;
    free(out);
}
```

# Warning!
- on visual studio you can compile it into debug and release mode and it will generate different hash depending on its mode!
- Compatible for 64bit platforms and c++ only!
- This version is only for testing. not for password hashing or else cause this version has inconsistent hashing bug
