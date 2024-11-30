


# 日志文件路径------------------------------------------------------------------------------------
$logFile = "C:\WindowsUpdateBackup\DisableWindowsUpdate.log"

# 记录日志并实时输出
function Write-Log {
    param (
        [ValidateSet("INFO", "WARNING", "ERROR")]
        [string]$Level = "INFO",
        [string]$Message
    )
    
    $timestamp = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
    $logMessage = "$timestamp [$Level] - $Message"
    
    # 确保日志目录存在
    $logDir = Split-Path -Path $logFile
    if (-Not (Test-Path -Path $logDir)) {
        try {
            New-Item -ItemType Directory -Path $logDir -Force | Out-Null
        }
        catch {
            Write-Host "无法创建日志目录 - $($_.Exception.Message)" -ForegroundColor Red
            return
        }
    }
    
    # 写入日志
    try {
        $logMessage | Out-File -FilePath $logFile -Append -Encoding utf8
    }
    catch {
        Write-Host "无法写入日志文件 - $($_.Exception.Message)" -ForegroundColor Red
    }
    
    # 控制台输出
    switch ($Level) {
        "INFO" { Write-Host $Message -ForegroundColor Green }
        "WARNING" { Write-Host $Message -ForegroundColor Yellow }
        "ERROR" { Write-Host $Message -ForegroundColor Red }
        default { Write-Host $Message }
    }
}

function Disable-WaaSMedicSvc {
    # 禁用 Windows Update Medic Service (WaaSMedicSvc)
    # -----------------------------

    $medicServiceRegistryPath = "HKLM:\SYSTEM\CurrentControlSet\Services\WaaSMedicSvc"
    $medicServiceBackupRegistryPath = "HKLM\SYSTEM\CurrentControlSet\Services\WaaSMedicSvc"
    $medicServiceBackupFile = "C:\WindowsUpdateBackup\WindowsUpdateRegistryBackup\WaaSMedicSvcBackup.reg"

    Write-Log -Level "INFO" -Message "正在备份 Windows Update Medic Service 注册表路径：$medicServiceBackupRegistryPath 到文件：$medicServiceBackupFile ..."
    try {
        reg export $medicServiceBackupRegistryPath $medicServiceBackupFile /y
        Write-Log -Level "INFO" -Message "Windows Update Medic Service 注册表备份成功。备份文件位于：$medicServiceBackupFile"
    }
    catch {
        Write-Log -Level "ERROR" -Message "备份 Windows Update Medic Service 注册表失败 - $($_.Exception.Message)"
    }

    try {
        # 检查是否存在 'Start' 键
        if (-not (Get-ItemProperty -Path $medicServiceRegistryPath -Name "Start" -ErrorAction SilentlyContinue | Select-Object -ExpandProperty Start -ErrorAction SilentlyContinue)) {
            Write-Log -Level "WARNING" -Message "'Start' 键不存在于 $medicServiceRegistryPath。尝试创建该键。"
            New-ItemProperty -Path $medicServiceRegistryPath -Name "Start" -Value 4 -PropertyType DWord -Force | Out-Null
            Write-Log -Level "INFO" -Message "已创建并设置 'Start' 为 4，Windows Update Medic Service 已禁用。"
        }
        else {
            # 设置 'Start' 键的值为 4（禁用）
            Set-ItemProperty -Path $medicServiceRegistryPath -Name "Start" -Value 4 -Type DWord
            Write-Log -Level "INFO" -Message "已设置 'Start' 为 4，Windows Update Medic Service 已禁用。"
        }

        # 处理 'FailureActions' 键
        Write-Log -Level "INFO" -Message "正在配置 'FailureActions' 键..."

        # 在 if 语句之前定义 $pointerSize 避免调用构造函数错误
        $pointerSize = [IntPtr]::Size
        $structSize = 4 + $pointerSize * 3  # dwResetPeriod + 3个指针

        # 检查 'FailureActions' 属性是否存在
        $serviceProperties = Get-ItemProperty -Path $medicServiceRegistryPath -ErrorAction SilentlyContinue
        $failureActionsExists = $serviceProperties.PSObject.Properties.Name -contains 'FailureActions'

        if (-not $failureActionsExists) {
            Write-Log -Level "WARNING" -Message "'FailureActions' 键不存在于 $medicServiceRegistryPath。将创建该键以禁用恢复操作。"

            # --------------------------------------------------------------------------------------------------------------------
            # --------参考微软文档https://learn.microsoft.com/zh-cn/windows/win32/api/winsvc/ns-winsvc-service_failure_actionsw
            # --------------------------------------------------------------------------------------------------------------------
        
            # 创建空的 FailureActions 数据
            $failureActionsData = New-Object Byte[] ($structSize)
            # dwResetPeriod 设置为 0
            [BitConverter]::GetBytes([UInt32]0).CopyTo($failureActionsData, 0)

            # cActions 设置为 0，表示没有失败操作
            $cActionsIndex = 4 + $pointerSize * 2
            [BitConverter]::GetBytes([UInt32]0).CopyTo($failureActionsData, $cActionsIndex)

            # 设置 'FailureActions' 值
            New-ItemProperty -Path $medicServiceRegistryPath -Name "FailureActions" -Value $failureActionsData -PropertyType Binary -Force | Out-Null
            Write-Log -Level "INFO" -Message "已创建并设置 'FailureActions'，禁用服务失败时的恢复操作。"
        }
        else {
            Write-Log -Level "INFO" -Message "'FailureActions' 键已存在，正在修改以禁用恢复操作。"

            # 获取当前的二进制数据
            $binaryData = $serviceProperties.FailureActions

            # 验证数据长度是否足够
            $expectedSize = 4 + $pointerSize * 3
            if ($binaryData.Length -ge $expectedSize) {
                # 设置 cActions 为 0
                $cActionsIndex = 4 + $pointerSize * 2
                [BitConverter]::GetBytes([UInt32]0).CopyTo($binaryData, $cActionsIndex)

                # 清空 lpsaActions 指针
                $lpsaActionsIndex = $cActionsIndex + 4
                $zeroPointer = New-Object Byte[] ($pointerSize)
                $zeroPointer.CopyTo($binaryData, $lpsaActionsIndex)

                # 更新 'FailureActions' 值
                Set-ItemProperty -Path $medicServiceRegistryPath -Name "FailureActions" -Value $binaryData -Type Binary -Force
                Write-Log -Level "INFO" -Message "成功修改 'FailureActions' 的二进制值，已禁用恢复操作。"
            }
            else {
                Write-Log -Level "ERROR" -Message "'FailureActions' 数据长度不足或结构不完整，无法修改。"
            }
        }

    }
    catch {
        Write-Log -Level "ERROR" -Message "禁用 Windows Update Medic Service 失败 - $($_.Exception.Message)"
    }

    # 停止 WaaSMedicSvc 服务
    try {
        Write-Log -Level "INFO" -Message "正在停止 Windows Update Medic Service 服务（WaaSMedicSvc）..."
        Stop-Service -Name WaaSMedicSvc -Force
        Write-Log -Level "INFO" -Message "Windows Update Medic Service 服务已停止。"
    }
    catch {
        Write-Log -Level "ERROR" -Message "停止 Windows Update Medic Service 服务失败 - $($_.Exception.Message)"
    }


    # 验证 WaaSMedicSvc 服务状态
    Write-Log -Level "INFO" -Message "正在验证 Windows Update Medic Service 状态..."
    try {
        $medicService = Get-Service -Name WaaSMedicSvc -ErrorAction SilentlyContinue
        if ($medicService) {
            if ($medicService.Status -eq 'Stopped' -and $medicService.StartType -eq 'Disabled') {
                Write-Log -Level "INFO" -Message "验证成功：Windows Update Medic Service 已停止并禁用。"
            }
            else {
                Write-Log -Level "WARNING" -Message "警告：Windows Update Medic Service 未正确停止或禁用。当前状态 - 状态: $($medicService.Status), 启动类型: $($medicService.StartType)"
            }
        }
        else {
            Write-Log -Level "WARNING" -Message "警告：Windows Update Medic Service 未找到，可能已被删除。"
        }
    }
    catch {
        Write-Log -Level "ERROR" -Message "无法获取 Windows Update Medic Service 状态 - $($_.Exception.Message)"
    }
}

function Disable-UsoSvc {
    # 禁用 Update Orchestrator Service（UsoSvc）
    # -----------------------------

    $orchestratorServiceRegistryPath = "HKLM:\SYSTEM\CurrentControlSet\Services\UsoSvc"
    $orchestratorServiceBackupRegistryPath = "HKLM\SYSTEM\CurrentControlSet\Services\UsoSvc"
    $orchestratorServiceBackupFile = "C:\WindowsUpdateBackup\WindowsUpdateRegistryBackup\UsoSvcBackup.reg"

    Write-Log -Level "INFO" -Message "正在备份 Update Orchestrator Service 注册表路径：$orchestratorServiceRegistryPath 到文件：$orchestratorServiceBackupFile ..."
    try {
        reg export $orchestratorServiceBackupRegistryPath $orchestratorServiceBackupFile /y
        Write-Log -Level "INFO" -Message "Update Orchestrator Service 注册表备份成功。备份文件位于：$orchestratorServiceBackupFile"
    }
    catch {
        Write-Log -Level "ERROR" -Message "备份 Update Orchestrator Service 注册表失败 - $($_.Exception.Message)"
    }

    try {
        # 检查是否存在 'Start' 键
        if (-not (Get-ItemProperty -Path $orchestratorServiceRegistryPath -Name "Start" -ErrorAction SilentlyContinue | Select-Object -ExpandProperty Start -ErrorAction SilentlyContinue)) {
            Write-Log -Level "WARNING" -Message "'Start' 键不存在于 $orchestratorServiceRegistryPath。尝试创建该键。"
            New-ItemProperty -Path $orchestratorServiceRegistryPath -Name "Start" -Value 4 -PropertyType DWord -Force | Out-Null
            Write-Log -Level "INFO" -Message "已创建并设置 'Start' 为 4，Update Orchestrator Service 已禁用。"
        }
        else {
            # 设置 'Start' 键的值为 4（禁用）
            Set-ItemProperty -Path $orchestratorServiceRegistryPath -Name "Start" -Value 4 -Type DWord
            Write-Log -Level "INFO" -Message "已设置 'Start' 为 4，Update Orchestrator Service 已禁用。"
        }

        # 处理 'FailureActions' 键
        Write-Log -Level "INFO" -Message "正在配置 'FailureActions' 键..."

        # 在 if 语句之前定义 $pointerSize 避免调用构造函数错误
        $pointerSize = [IntPtr]::Size
        $structSize = 4 + $pointerSize * 3

        # 检查 'FailureActions' 属性是否存在
        $serviceProperties = Get-ItemProperty -Path $orchestratorServiceRegistryPath -ErrorAction SilentlyContinue
        $failureActionsExists = $serviceProperties.PSObject.Properties.Name -contains 'FailureActions'

        if (-not $failureActionsExists) {
            Write-Log -Level "WARNING" -Message "'FailureActions' 键不存在于 $orchestratorServiceRegistryPath。将创建该键以禁用恢复操作。"

            # --------------------------------------------------------------------------------------------------------------------
            # --------参考微软文档https://learn.microsoft.com/zh-cn/windows/win32/api/winsvc/ns-winsvc-service_failure_actionsw
            # --------------------------------------------------------------------------------------------------------------------
        
            # 创建空的 FailureActions 数据
            $failureActionsData = New-Object Byte[] ($structSize)
            # dwResetPeriod 设置为 0
            [BitConverter]::GetBytes([UInt32]0).CopyTo($failureActionsData, 0)

            # cActions 设置为 0，表示没有失败操作
            $cActionsIndex = 4 + $pointerSize * 2
            [BitConverter]::GetBytes([UInt32]0).CopyTo($failureActionsData, $cActionsIndex)

            # 设置 'FailureActions' 值
            New-ItemProperty -Path $orchestratorServiceRegistryPath -Name "FailureActions" -Value $failureActionsData -PropertyType Binary -Force | Out-Null
            Write-Log -Level "INFO" -Message "已创建并设置 'FailureActions'，禁用服务失败时的恢复操作。"
        }
        else {
            Write-Log -Level "INFO" -Message "'FailureActions' 键已存在，正在修改以禁用恢复操作。"

            # 获取当前的二进制数据
            $binaryData = $serviceProperties.FailureActions

            # 验证数据长度是否足够
            $expectedSize = 4 + $pointerSize * 3
            if ($binaryData.Length -ge $expectedSize) {
                # 设置 cActions 为 0
                $cActionsIndex = 4 + $pointerSize * 2
                [BitConverter]::GetBytes([UInt32]0).CopyTo($binaryData, $cActionsIndex)

                # 清空 lpsaActions 指针
                $lpsaActionsIndex = $cActionsIndex + 4
                $zeroPointer = New-Object Byte[] ($pointerSize)
                $zeroPointer.CopyTo($binaryData, $lpsaActionsIndex)

                # 更新 'FailureActions' 值
                Set-ItemProperty -Path $orchestratorServiceRegistryPath -Name "FailureActions" -Value $binaryData -Type Binary -Force
                Write-Log -Level "INFO" -Message "成功修改 'FailureActions' 的二进制值，已禁用恢复操作。"
            }
            else {
                Write-Log -Level "ERROR" -Message "'FailureActions' 数据长度不足或结构不完整，无法修改。"
            }
        }

    }
    catch {
        Write-Log -Level "ERROR" -Message "禁用 Update Orchestrator Service 时发生错误 - $($_.Exception.Message)"
    }

    # 停止 Update Orchestrator Service 服务
    try {
        Write-Log -Level "INFO" -Message "正在停止 Update Orchestrator Service 服务（UsoSvc）..."
        Stop-Service -Name UsoSvc -Force
        Write-Log -Level "INFO" -Message "Update Orchestrator Service 服务已停止。"
    }
    catch {
        Write-Log -Level "ERROR" -Message "停止 Update Orchestrator Service 服务失败 - $($_.Exception.Message)"
    }

    # 禁用 Update Orchestrator Service 服务
    try {
        Write-Log -Level "INFO" -Message "正在禁用 Update Orchestrator Service 服务（UsoSvc）..."
        Set-Service -Name UsoSvc -StartupType Disabled
        # 禁止自动恢复 Update Orchestrator Service 服务
        Write-Log -Level "INFO" -Message "正在禁用 Update Orchestrator Service 服务的恢复选项..."
        & sc.exe failure UsoSvc reset= 0 actions= "" command= ""
        Write-Log -Level "INFO" -Message "Update Orchestrator Service 服务恢复选项已禁用。"
        Write-Log -Level "INFO" -Message "Update Orchestrator Service 服务已禁用。"
    }
    catch {
        Write-Log -Level "ERROR" -Message "禁用 Update Orchestrator Service 服务失败 - $($_.Exception.Message)"
    }

    # 验证 Update Orchestrator Service 服务状态
    Write-Log -Level "INFO" -Message "正在验证 Update Orchestrator Service 服务状态..."
    try {
        $service = Get-Service -Name UsoSvc
        if ($service.Status -eq 'Stopped' -and $service.StartType -eq 'Disabled') {
            Write-Log -Level "INFO" -Message "验证成功：Update Orchestrator Service 服务已停止并禁用。"
        }
        else {
            Write-Log -Level "WARNING" -Message "警告：Update Orchestrator Service 服务未正确停止或禁用。当前状态 - 状态: $($service.Status), 启动类型: $($service.StartType)"
        }
    }
    catch {
        Write-Log -Level "ERROR" -Message "无法获取 Update Orchestrator Service 服务状态 - $($_.Exception.Message)"
    }

}

function Disable-WindowsUpdateTasks {
    param (
        [string]$TaskPath = "\Microsoft\Windows\WindowsUpdate\",
        [string]$BackupDir = "C:\WindowsUpdateBackup\ScheduledTask"
    )

    # 创建备份目录（如果不存在）
    if (!(Test-Path $BackupDir)) {
        try {
            New-Item -ItemType Directory -Path $BackupDir -Force | Out-Null
            Write-Log -Message "已创建备份目录 $BackupDir。"
        }
        catch {
            Write-Log -Level "ERROR" -Message "无法创建备份目录 $BackupDir。错误：$($_.Exception.Message)"
            return
        }
    }
    else {
        Write-Log -Message "备份目录 $BackupDir 已存在。"
    }

    # 获取所有 Windows Update 相关的计划任务
    try {
        $tasks = Get-ScheduledTask -TaskPath $TaskPath
        if ($tasks) {
            foreach ($task in $tasks) {
                $taskName = $task.TaskName
                $exportPath = Join-Path $BackupDir "$taskName.xml"

                # 导出计划任务到备份目录
                try {
                    $xml = Export-ScheduledTask -TaskName $taskName -TaskPath $TaskPath
                    $xml | Out-File -FilePath $exportPath -Encoding UTF8
                    Write-Log -Message "已导出计划任务 $taskName 到 $exportPath。"
                }
                catch {
                    Write-Log -Level "ERROR" -Message "无法导出计划任务 $taskName。错误：$($_.Exception.Message)"
                    continue
                }

                # 删除计划任务
                try {
                    Unregister-ScheduledTask -TaskName $taskName -TaskPath $TaskPath -Confirm:$false
                    Write-Log -Message "已删除计划任务 $taskName。"
                }
                catch {
                    Write-Log -Level "ERROR" -Message "无法删除计划任务 $taskName。错误：$($_.Exception.Message)"
                }
            }
        }
        else {
            Write-Log -Message "在路径 $TaskPath 下未找到任何计划任务。"
        }
    }
    catch {
        Write-Log -Level "ERROR" -Message "无法获取计划任务。错误：$($_.Exception.Message)"
    }
}

# 检查并轮转日志文件
$maxLogSize = 10MB
if (Test-Path $logFile) {
    $logSize = (Get-Item $logFile).Length
    if ($logSize -gt $maxLogSize) {
        $backupLogFile = "C:\WindowsUpdateBackup\DisableWindowsUpdate_$(Get-Date -Format 'yyyyMMddHHmmss').log"
        try {
            Copy-Item -Path $logFile -Destination $backupLogFile
            Clear-Content -Path $logFile
            Write-Log -Level "INFO" -Message "日志文件已备份并清空。备份文件：$backupLogFile"
        }
        catch {
            Write-Log -Level "ERROR" -Message "日志轮转失败 - $($_.Exception.Message)"
        }
    }
}

Write-Log -Level "INFO" -Message "开始执行脚本：禁用 Windows 更新以及手动更新。"
Write-Log -Level "INFO" -Message "请确保您已经备份了注册表，并且系统恢复点已创建。"

# 检查管理员权限-----------------------------------------------------------------------------------------------------------
if (-not ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
    Write-Log -Level "ERROR" -Message "请以管理员身份运行此脚本。脚本已退出。"
    exit
}
else {
    Write-Log -Level "INFO" -Message "已确认以管理员身份运行脚本。"
}

# 确保备份目录存在
$backupDir = "C:\WindowsUpdateBackup\WindowsUpdateRegistryBackup"
if (-not (Test-Path $backupDir)) {
    try {
        New-Item -Path $backupDir -ItemType Directory -Force | Out-Null
        Write-Log -Level "INFO" -Message "已创建备份目录：$backupDir"
    }
    catch {
        Write-Log -Level "ERROR" -Message "创建备份目录失败 - $($_.Exception.Message)"
    }
}

# 预定义创建注册表路径
$registryPath = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate\AU"

# 如果注册表路径不存在，则创建它
if (-not (Test-Path $registryPath)) {
    try {
        New-Item -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate" -Name "AU" -Force | Out-Null
        Write-Log -Level "INFO" -Message "已创建注册表路径：$registryPath"
    }
    catch {
        Write-Log -Level "ERROR" -Message "创建注册表路径失败 - $($_.Exception.Message)"
    }
}
else {
    Write-Log -Level "INFO" -Message "注册表路径已存在：$registryPath"
}

# 备份注册表
$backupRegistryPath = "HKLM\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate"
$backupFile = "C:\WindowsUpdateBackup\WindowsUpdateRegistryBackup\WindowsUpdateBackup.reg"

Write-Log -Level "INFO" -Message "正在备份注册表路径：$backupRegistryPath 到文件：$backupFile ..."
try {
    reg export $backupRegistryPath $backupFile /y
    Write-Log -Level "INFO" -Message "注册表备份成功。备份文件位于：$backupFile"
}
catch {
    Write-Log -Level "ERROR" -Message "备份注册表失败 - $($_.Exception.Message)"
}

# 禁用自动更新
try {
    Set-ItemProperty -Path $registryPath -Name "NoAutoUpdate" -Value 1 -Type DWord
    Write-Log -Level "INFO" -Message "已设置 'NoAutoUpdate' 为 1，自动更新已禁用。"
}
catch {
    Write-Log -Level "ERROR" -Message "设置 'NoAutoUpdate' 失败 - $($_.Exception.Message)"
}

# 禁用手动更新
$manualUpdateRegistryPath = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate"
try {
    # 确保 DisableUXWUAccess 键存在
    if (-not (Get-ItemProperty -Path $manualUpdateRegistryPath -Name "DisableUXWUAccess" -ErrorAction SilentlyContinue)) {
        New-ItemProperty -Path $manualUpdateRegistryPath -Name "DisableUXWUAccess" -Value 1 -PropertyType DWord -Force | Out-Null
        Write-Log -Level "INFO" -Message "已创建并设置 'DisableUXWUAccess' 为 1，手动更新已禁用。"
    }
    else {
        Set-ItemProperty -Path $manualUpdateRegistryPath -Name "DisableUXWUAccess" -Value 1 -Type DWord
        Write-Log -Level "INFO" -Message "已设置 'DisableUXWUAccess' 为 1，手动更新已禁用。"
    }
}
catch {
    Write-Log -Level "ERROR" -Message "设置 'DisableUXWUAccess' 失败 - $($_.Exception.Message)"
}

# 错误处理和验证
Write-Log -Level "INFO" -Message "正在验证注册表更改是否成功..."
try {
    # 检查自动更新禁用是否成功
    $currentValue = Get-ItemProperty -Path $registryPath -Name "NoAutoUpdate"
    if ($currentValue.NoAutoUpdate -eq 1) {
        Write-Log -Level "INFO" -Message "验证成功：'NoAutoUpdate' 已设置为 1，Windows 自动更新已禁用。"
    }
    else {
        Write-Log -Level "WARNING" -Message "警告：'NoAutoUpdate' 未正确设置。当前值为 $($currentValue.NoAutoUpdate)"
    }

    # 检查手动更新禁用是否成功
    $manualUpdateValue = Get-ItemProperty -Path $manualUpdateRegistryPath -Name "DisableUXWUAccess"
    if ($manualUpdateValue.DisableUXWUAccess -eq 1) {
        Write-Log -Level "INFO" -Message "验证成功：'DisableUXWUAccess' 已设置为 1，手动更新已禁用。"
    }
    else {
        Write-Log -Level "WARNING" -Message "警告：'DisableUXWUAccess' 未正确设置。当前值为 $($manualUpdateValue.DisableUXWUAccess)"
    }
}
catch {
    Write-Log -Level "ERROR" -Message "验证注册表设置失败 - $($_.Exception.Message)"
}

# 停止 Windows Update 服务
try {
    Write-Log -Level "INFO" -Message "正在停止 Windows Update 服务（wuauserv）..."
    Stop-Service -Name wuauserv -Force
    Write-Log -Level "INFO" -Message "Windows Update 服务已停止。"
}
catch {
    Write-Log -Level "ERROR" -Message "停止 Windows Update 服务失败 - $($_.Exception.Message)"
}

# 禁用 Windows Update 服务
try {
    Write-Log -Level "INFO" -Message "正在禁用 Windows Update 服务（wuauserv）..."
    Set-Service -Name wuauserv -StartupType Disabled
    # 禁止自动恢复 Windows Update 服务
    Write-Log -Level "INFO" -Message "正在禁用 Windows Update 服务的恢复选项..."
    & sc.exe failure wuauserv reset= 0 actions= "" command= ""
    Write-Log -Level "INFO" -Message "Windows Update 服务恢复选项已禁用。"
    Write-Log -Level "INFO" -Message "Windows Update 服务已禁用。"
}
catch {
    Write-Log -Level "ERROR" -Message "禁用 Windows Update 服务失败 - $($_.Exception.Message)"
}

# 验证 Windows Update 服务状态
Write-Log -Level "INFO" -Message "正在验证 Windows Update 服务状态..."
try {
    $service = Get-Service -Name wuauserv
    if ($service.Status -eq 'Stopped' -and $service.StartType -eq 'Disabled') {
        Write-Log -Level "INFO" -Message "验证成功：Windows Update 服务已停止并禁用。"
    }
    else {
        Write-Log -Level "WARNING" -Message "警告：Windows Update 服务未正确停止或禁用。当前状态 - 状态: $($service.Status), 启动类型: $($service.StartType)"
    }
}
catch {
    Write-Log -Level "ERROR" -Message "无法获取 Windows Update 服务状态 - $($_.Exception.Message)"
}

# 禁用 Windows Update Medic Service (WaaSMedicSvc)-------------------------------------------------------------------------------
Disable-WaaSMedicSvc

# 禁用 Update Orchestrator Service（UsoSvc）-----------------------------------------------
Disable-UsoSvc

# 删除 Windows Update 计划任务  --------------------------------------------------
Disable-WindowsUpdateTasks


Write-Log -Level "INFO" -Message "脚本执行完成。请重启计算机以确保所有更改生效。"
