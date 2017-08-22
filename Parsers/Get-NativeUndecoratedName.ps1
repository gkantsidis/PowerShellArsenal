$DbgHelp = Invoke-LoadLibrary dbghelp
$undecorate = New-DllExportFunction -Module $DbgHelp -ProcedureName UnDecorateSymbolName -Parameters ([string], [System.Text.StringBuilder], [UInt32], [UInt32]) -ReturnType ([Int])

function Get-NativeUndecoratedName {
    [CmdletBinding()]
    param(
        [ValidateNotNullOrEmpty()]
        [string]$DecoratedSymbol
    )

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