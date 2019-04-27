# DLLHijacker

相关的文章在个人博客里[https://kiwings.github.io/2019/04/04/th-DLL%E5%8A%AB%E6%8C%81/]
代码其实很简单，将网上能找到的x86与x64的劫持方式做了一个整合的脚本。
感谢前人，让我增长了知识、少走了许多弯路。

该脚本的功能是生成DLL劫持时所需的源文件(利用函数转发的劫持方式)。
输入是一个DLL文件，然后判断目标DLL文件的位数并生成对应的vs2019的项目文件夹。
打开项目后，修改Hijack函数体，可以只是修改shellcode、也可以将shellcode的加载方式一并修改(该加载方式源自于MSF、特征明显，无法绕过杀软)。

----

Usage:  
    1. python3 ./DLLHijacker.py target.dll  
    2. use vs2019 to open the project, and rewrite the Hijack function,You can just modify the shellcode or modify the way      shellcode is executed at the same time.
    
