# VTR3Hook
从0开始编写Windows 虚拟化 hook ring3 代码的工程 支持(AMD/Intel)
## 组成
### AMDVTDriver
AMD SVM 驱动，从 [StartAMDVHookDriverFromNone](https://github.com/Liu-Zhiying/StartAMDVHookDriverFromNone) 而来，为了ring 3 hook 代码有修改
### StartVTXHookDriverFromNone
Intel VTX 驱动，从 [StartVTXHookDriverFromNone](https://github.com/Liu-Zhiying/StartVTXHookDriverFromNone) 而来，为了ring 3 hook 代码有修改
## VTR3Hook
测试用例
## VTR3HookLib
驱动的用户态接口
