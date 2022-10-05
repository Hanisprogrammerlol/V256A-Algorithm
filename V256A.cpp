/*
 MIT License

Copyright (c) 2022 Hanisprogrammerlol

Permission is hereby granted, free of charge, to any person obtaining a copy
of this software and associated documentation files (the "Software"), to deal
in the Software without restriction, including without limitation the rights
to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
copies of the Software, and to permit persons to whom the Software is
furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in all
copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
SOFTWARE.

this is an example of V256A the main program of V256A is core.cpp and core.h
*/

#include "core.hpp"

int main()
{
    //this is basic of V256A
    //text variable must be pointer if its not pointers V256A_GenerateHash will not work
    const char* text = "test";
    //output variables must use malloc(170) for initialization (because V256A outputs char with 170 bytes, malloc must use 170 bytes)
    char* out = (char*)malloc(170);
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
    std::cout << out << "\n\n";
    //the memcpy will reset value inside variable out into blank string
    //if you dont reset the value inside out it will print out the same output even if you generate hash 10 times
    memcpy(out, "", sizeof(""));
    //or you can use this method to generate new hash
    V256A::CreateHash(text, out, 32, 32, 512);
    std::cout << out; 
    free(out);
}
