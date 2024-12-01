[English](README.en.md)

此项目用于禁用Windows11更新

使用方法：使用管理员权限的powershell下运行。

实现原理:
1: 对注册表 HKLM:\SYSTEM\CurrentControlSet\Services\WaaSMedicSvc 进行操作
2: 对注册表 HKLM:\SYSTEM\CurrentControlSet\Services\UsoSvc 进行操作
3: 对注册表 HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate 进行操作
4: 对注册表 HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate\AU 进行操作
5: 操作Windows Updates计划任务
6: 通过上注册表，以及额外添加禁用Windows Updates相关服务

备份路径
默认 C:\WindowsUpdateBackup 目录下
日志路径
C:\WindowsUpdateBackup\DisableWindowsUpdate.log

待优化问题： 
1:  32位和64位操作系统二进制数据不同，注册表中的FailureActions键结构待优化。
2:  部分代码逻辑待优化
