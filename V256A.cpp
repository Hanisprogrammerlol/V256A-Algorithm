/*
* MIT License

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

#include "core.h"

int main()
{
    //this is basic of V256A
    //text variable must be pointer if its not pointers V256A_GenerateHash will not work
    const char* text = "test123";
    V256A_Init();
    V256A_Digest();
    V256A_CalcChunks(text[0]);
    V256A_GenerateHash(text, 32, 32, 512);
    //V256A Sweep will sweep all data from core.h struct
    V256A_Sweep();

    //or you can do this
    const char* text = "test123";
    V256A_Digest();
    V256A_CalcChunks(text[0]);
    V256A_Init();
    //generate hash must be last
    V256A_GenerateHash(text, 32, 32, 512);
    V256A_Sweep();
}
