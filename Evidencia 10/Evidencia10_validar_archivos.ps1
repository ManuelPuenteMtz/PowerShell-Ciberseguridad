function Validar-Archivo {
    param (
        [string]$Ruta
    )

    # Generar nombre del reporte con fecha al final (formato ddMMyyyy)
    $fechaArchivo = Get-Date -Format "ddMMyyyy"
    $Reporte = ([Environment]::GetFolderPath("Desktop") + "\ReporteValidacion_$fechaArchivo.txt")

    $resultado = ""

    try {
        if (Test-Path $Ruta) {
            $contenido = Get-Content $Ruta -ErrorAction Stop
            $resultado = "Archivo encontrado y accesible: $Ruta"
        } else {
            throw "El archivo no existe."
        }
    }
    catch {
        $resultado = "Error: $_"
    }
    finally {
        Write-Host "Validación finalizada para: $Ruta" -ForegroundColor Cyan  

        $fecha = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
        $linea = "[$fecha] $resultado"
        Add-Content -Path $Reporte -Value $linea
        Write-Host "Reporte guardado en: $Reporte" -ForegroundColor Green
    }

    return $resultado
}