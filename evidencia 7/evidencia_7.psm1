# ============================================================================
# = Evidencia 7: Automatización de tareas forenses con PowerShell en Windows =
# ============================================================================
# Por: 
# MANUEL DE JESUS PUENTE MARTINEZ
# ROGELIO DE LLANO SALAZAR


# 1. Extracción de eventos relevantes del Visor de eventos (registros de eventos)
function Get-SuspiciousEvents {
    <#
    .SYNOPSIS
        Comando para mostrar los eventos inusuales o sospechosos
    .DESCRIPTION
        Con este comando se extrae los eventos de Sistema, Aplicaciones y Seguridad y los filtra para encontrar todos los ventos sospechosos
    .PARAMETER MaxEvents
        Este parametro define el numero máximo de eventos ques se analizarán en cada log.
    .PARAMETER OutPath
        Especifica la ruta y el nombre del archivo CSV donde se guardarán los resultados
    #>
    param(
        [int]$MaxEvents = 2000,
        [string]$OutputPath = "$PWD\eventos_sospechosos_$(Get-Date -Format dd_MM_yyyy).csv",
        [switch]$DontSaveReport
    )

    # Logs a revisar
    $logs = "System", "Application", "Security"

    # IDs de eventos sospechosos comunes
    $idsSospechosos = 4625, 4672, 4648, 6008, 41, 7034, 7031, 1000, 1002

    # Palabras clave en los mensajes
    $keywords = "fail","denied","unauthorized","error","critical","malware","attack"

    foreach ($log in $logs) {
        try {
            Get-WinEvent -LogName $log -MaxEvents $MaxEvents |
            Where-Object {
                ($_.Id -in $idsSospechosos) -or
                ($_.LevelDisplayName -in "Error","Critical","Warning") -or
                ($keywords | ForEach-Object { $_match = $_; if ($_.Message -match $_match) { $true } })
            } |
            Select-Object @{Name="LogName";Expression={$log}},
                          TimeCreated,
                          Id,
                          LevelDisplayName,
                          @{Name="Message";Expression={$_.Message -replace "`r`n"," "}} |
                          ForEach-Object {
                                if (-not $DontSaveReport) {
                                    $_ | Export-Csv -Path $OutputPath -NoTypeInformation -Encoding UTF8 -Append
                                }
                            Write-Output $_
                        }

        }
        catch {
            Write-Warning "No se pudo acceder al log $log (¿ejecutaste como Administrador?)."
        }
    }
    if (-not $DontSaveReport) {
        Write-Host "Exportación completada. Archivo: $OutputPath"
    }
}


# 2. Correlación de procesos activos con conexiones de red
#Get-InternetProcesses
function Get-InternetProcesses {
    [CmdletBinding()]
    param(
        [switch]$DontSaveReport
    )

    $connections = Get-NetTCPConnection | Where-Object State -eq 'Established'

    $results = foreach ($conn in $connections) {
        try {
            $proc = Get-Process -Id $conn.OwningProcess -ErrorAction Stop
        } catch {
            continue
        }

        [PSCustomObject]@{
            ProcessName   = $proc.ProcessName
            PID           = $conn.OwningProcess
            LocalAddress  = $conn.LocalAddress
            LocalPort     = $conn.LocalPort
            RemoteAddress = $conn.RemoteAddress
            RemotePort    = $conn.RemotePort
            State         = $conn.State
        }
    }

    if (-not $DontSaveReport) {
        $results | Export-Csv -Path "$PWD\reporte_procesos_internet_$(Get-Date -Format dd_MM_yyyy).csv" -NoTypeInformation -Encoding UTF8
    }

    return $results
}


#Get-UnsignedProcesses
function Get-UnsignedProcesses {
    <#
    .SYNOPSIS
        Obtiene los procesos sin firma digital y los devuelve como objetos.
    .DESCRIPTION
        Recorre los procesos del sistema, verifica su firma digital y los devuelve
    #>
    [CmdletBinding()]
    param()

    $unsignedList = @()

    foreach ($process in Get-Process) {
        $filePath = $null
        try {
            $filePath = $process.Path
        } catch {
            continue
        }

        if ($null -ne $filePath) {
            try {
                $signature = Get-AuthenticodeSignature -FilePath $filePath
            } catch {
                continue
            }

            if ($signature.Status -eq 'NotSigned' -or $signature.Status -eq 'Unknown') {
                $unsignedList += [PSCustomObject]@{
                    Name        = $process.Name
                    Id          = $process.Id
                    FilePath    = $filePath
                    Status      = $signature.Status
                    Description = $process.Description
                }
            }
        }
    }

    return $unsignedList
}




# 3. Investigación de direcciones IP remotas mediante AbuseIPDB

function Get-SuspiciousInternetProcesses {
    <#
    .SYNOPSIS
        Verifica conexiones a Internet y consulta AbuseIPDB.
    .PARAMETER Threshold
        Sensibilidad 0-100
    .PARAMETER DontSaveReport
        No guardar el reporte
    #>
    [CmdletBinding()]
    param(
        [int] $Threshold = 10,
        [switch]$DontSaveReport
    )

    $results = @()
    $TCPConnections = Get-NetTCPConnection | Where-Object State -eq "Established"
    $Processes = Get-Process

    foreach ($connection in $TCPConnections) {
        $ip = $connection.RemoteAddress
        try {
            $response = Invoke-RestMethod -Method Get `
                -Uri "https://api.abuseipdb.com/api/v2/check?ipAddress=$ip" `
                -Headers @{
                    "Key"    = "1b72796d70c1d1d45a663087a24e08785b35e10d47abbf3596f7ac2611aa286bd3900a32fb4c5a1c"
                    "Accept" = "application/json"
                }

            $score = $response.data.abuseConfidenceScore
            if ($score -ge $Threshold) {
                $proc = $Processes | Where-Object Id -eq $connection.OwningProcess
                if ($proc) {
                    $results += [PSCustomObject]@{
                        Timestamp          = (Get-Date).ToString("s")
                        ProcessName        = $proc.ProcessName
                        PID                = $proc.Id
                        RemoteAddress      = $ip
                        AbuseConfidencePct = $score
                        TotalReports       = $response.data.totalReports
                    }
                }
            }
        } catch {
            Write-Warning "Error consultando AbuseIPDB para $ip"
        }
    }

    if (-not $DontSaveReport) {
        if ($results.Count -gt 0) {
            $results |
                Sort-Object AbuseConfidencePct -Descending |
                Export-Csv -Path "$PWD\processos_sospechosos_abuseipdb_$(Get-Date -Format dd_MM_yyyy).csv" -NoTypeInformation -Encoding UTF8
        } else {
            Write-Host "No se encontraron IPs con puntaje de abuso mayor a $Threshold."
        }
    }

    return $results
}

function Get-FullForensicAnalysis {
    [CmdletBinding()]
    param(
        [string]$OutputPath = (".\reporte_forense_completo_{0}.csv" -f (Get-Date -Format "dd_MM_yyyy_HH_mm")),
        [switch]$DontSaveReport
    )

    Write-Host "=== Iniciando analisis forense completo ===" -ForegroundColor Cyan

    Write-Host "[1/3] Correlacionando procesos activos con conexiones de red..." -ForegroundColor Yellow
    $internetProcs = Get-InternetProcesses -DontSaveReport

    Write-Host "[2/3] Detectando procesos sin firma digital..." -ForegroundColor Yellow
    $unsignedProcs = Get-UnsignedProcesses

    Write-Host "[3/3] Consultando IPs sospechosas en AbuseIPDB..." -ForegroundColor Yellow
    $suspiciousIPs = Get-SuspiciousInternetProcesses -Threshold 10 -DontSaveReport

    Write-Host "Correlacionando resultados..." -ForegroundColor Green

    # Mapas con claves normalizadas a string
    $internetByPid = @{}
    foreach ($row in $internetProcs) {
        $k = "{0}" -f $row.PID
        if (-not $internetByPid.ContainsKey($k)) {
            $internetByPid[$k] = [System.Collections.Generic.HashSet[string]]::new()
        }
        if ($row.RemoteAddress) { [void]$internetByPid[$k].Add($row.RemoteAddress) }
    }

    $unsignedSet = @{}
    foreach ($u in $unsignedProcs) {
        $unsignedSet["{0}" -f $u.Id] = $true
    }

    $suspiciousByPid = @{}
    foreach ($s in $suspiciousIPs) {
        $k = "{0}" -f $s.PID
        if (-not $suspiciousByPid.ContainsKey($k)) {
            $suspiciousByPid[$k] = [System.Collections.Generic.HashSet[string]]::new()
        }
        if ($s.RemoteAddress) { [void]$suspiciousByPid[$k].Add($s.RemoteAddress) }
    }

    # Inventario de TODOS los procesos
    $correlacion = @()
    foreach ($p in Get-Process) {
        $pid = $p.Id
        $k   = "{0}" -f $pid

        $hasInternet   = $internetByPid.ContainsKey($k)
        $isUnsigned    = $unsignedSet.ContainsKey($k)
        $hasSuspicious = $suspiciousByPid.ContainsKey($k)
        if ( $hasInternet -eq "False" -or $isUnsigned -eq "False" -or $hasSuspicious -eq "False") {
            $correlacion += [PSCustomObject]@{
                ProcessName     = $p.ProcessName
                PID             = $pid
                HasInternet     = $hasInternet
                Unsigned        = $isUnsigned
                SuspiciousIP    = $hasSuspicious
            }
        }
    }

    if (-not $DontSaveReport) {
        $correlacion |
            Sort-Object -Property @{Expression='SuspiciousIP';Descending=$true},
                                 @{Expression='Unsigned';Descending=$true},
                                 @{Expression='HasInternet';Descending=$true},
                                 'ProcessName' |
            Export-Csv -Path $OutputPath -NoTypeInformation -Encoding UTF8
        Write-Host "Reporte generado en: $OutputPath" -ForegroundColor Cyan
    }

    Write-Host "=== Análisis forense completo finalizado ===" -ForegroundColor Cyan
    return $correlacion
}