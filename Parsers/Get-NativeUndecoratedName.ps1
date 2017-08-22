$DbgHelp = Invoke-LoadLibrary dbghelp -ErrorAction SilentlyContinue
if ($DbgHelp -ne $null) {
    $undecorate = New-DllExportFunction -Module $DbgHelp -ProcedureName UnDecorateSymbolName -Parameters ([string], [System.Text.StringBuilder], [UInt32], [UInt32]) -ReturnType ([Int])
} else {
    $undecorate = $null
}

function Get-NativeUndecoratedName {
    [CmdletBinding()]
    param(
        [ValidateNotNullOrEmpty()]
        [string]$DecoratedSymbol
    )

    if ($undecorate -eq $null) {
        Write-Warning -Message "Cannot find the dbghelp library; cannot get undecorated name."
        [PSCustomObject]@{
            SymbolType = 'C/C++'
            Symbol     = $DecoratedSymbol
        }

        return
    }

    if ($DecoratedSymbol.StartsWith('?')) {
        $StrBuilder = New-Object Text.Stringbuilder(1024)
        $undecorate.Invoke($DecoratedSymbol, $StrBuilder, $StrBuilder.Capacity, 0) | Out-Null

        [PSCustomObject]@{
            SymbolType = 'C++'
            Symbol     = $StrBuilder.ToString()
        }
    } else {
        [PSCustomObject]@{
            SymbolType = 'C'
            Symbol     = $DecoratedSymbol
        }
    }
}