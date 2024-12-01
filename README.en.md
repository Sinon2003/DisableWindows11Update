[简体中文](README.md)

# DisableWindows11Update
This project is used to disable Windows 11 updates.

Run under PowerShell with administrative privileges.


Implementation Principles:


Perform operations on the registry key HKLM:\SYSTEM\CurrentControlSet\Services\WaaSMedicSvc.

Perform operations on the registry key HKLM:\SYSTEM\CurrentControlSet\Services\UsoSvc.

Perform operations on the registry key HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate.

Perform operations on the registry key HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate\AU.

Modify Windows Updates scheduled tasks.

Disable Windows Updates-related services through the aforementioned registry operations and by adding additional configurations.


Backup Path:


Default: C:\WindowsUpdateBackup directory.

Log Path:


C:\WindowsUpdateBackup\DisableWindowsUpdate.log.


Optimization Issues: 


1:  The binary data differs between 32-bit and 64-bit operating systems, and the structure of the FailureActions key in the registry requires further optimization.

2:  Some code logic requires further optimization.
