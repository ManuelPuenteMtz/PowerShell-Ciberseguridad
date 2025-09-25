# ============================================================================
# = Evidencia 7: Automatizacion de tareas forenses con PowerShell en Windows =
# ============================================================================
# Por: 
# MANUEL DE JESUS PUENTE MARTINEZ
# ROGELIO DE LLANO SALAZAR


$art = @"
      .~~~~`\~~\
     ;       ~~ \
     |           ;
 ,--------,______|---.
/          \-----`    \ 
`.__________`-_______-'  _____                             
   / \  _   _| |_ ___ |  ___|__  _ __ ___ _ __  ___  ___ 
  / _ \| | | | __/ _ \| |_ / _ \| '__/ _ \ '_ \/ __|/ _ \
 / ___ \ |_| | || (_) |  _| (_) | | |  __/ | | \__ \  __/
/_/   \_\__,_|\__\___/|_|  \___/|_|  \___|_| |_|___/\___|
"@

Write-Host $art -ForegroundColor Green

Write-Output ""
Write-Output "========================================================="
Write-Output "= Bienvenido a la herramienta de automatizacion forense ="
Write-Output "========================================================="
Write-Output ""
Write-Output "Asegurese de ejecutar este script en la misma carpeta de evidencia_7.psm1"
Import-Module .\evidencia_7.psm1 -ErrorAction Stop
Write-Output "Seleccione la tarea que desea realizar:"
Write-Output "1. Extraccion de eventos relevantes del Visor de eventos (registros de eventos)"
Write-Output "2. Correlacion de procesos activos con conexiones de red"
Write-Output "3. Investigacion de direcciones IP remotas mediante AbuseIPDB"
Write-Output "4. Obtener los procesos no firmados en el sistema"
Write-Output "5. Ejecutar todas las tareas anteriores"
Write-Output "6. Ejecutar un reporte completo"
Write-Output "7. Salir"

[int] $opcion = Read-Host "Ingrese el numero de la opcion deseada (1-7)"

do {
    switch ($opcion) {
    1 {
       Get-SuspiciousEvents
    } 
    2 {
       Get-InternetProcesses
    }
    3 {
       Get-SuspiciousInternetProcesses
    }
    4 {
       Get-UnsignedProcesses
    }
    5 {
       Get-SuspiciousEvents
       Get-SuspiciousInternetProcesses
       Get-InternetProcesses
       Get-UnsignedProcesses
    }
    6 {
      Get-FullForensicAnalysis
    }
    7 {
        Write-Output "Saliendo"
        $salir = $true
    }
    Default {
        Write-Output "Error en la seleccion, por favor intente de nuevo."
    }
}
} while ($salir -ne $true -and ($opcion = Read-Host "Ingrese el numero de la opcion deseada (1-7)"))