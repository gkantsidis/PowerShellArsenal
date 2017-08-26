Enum ModuleTypeGuess {
    Native
    DotNet
    Unknown
}

class ModuleLocationInfo
{
    [string]$Name
    [int]$Distance
    [int]$Count
    [string]$Parent
    [string]$Location
    [ModuleTypeGuess]$ModuleType

    ModuleLocationInfo([string]$Name, [int]$Distance, [string]$Parent)
    {
        $this.Name = $Name
        $this.Distance = $Distance
        $this.Parent = $Parent
        $this.Location = [string]::Empty
        $this.ModuleType = [ModuleTypeGuess]::Unknown
        $this.Count = 1
    }
}

function Get-PEDependencies {
    <#
    .SYNOPSIS
    Collects the dependencies of an .EXE/.DLL on other dependencies.

    .DESCRIPTION
    Open a Portable Executable (PE) file (.EXE or .DLL) and search for its dependencies
    on other modules (.DLLs); continue recursively on their dependencies.

    If the target PE is not in the same directory it will also search in the PATH.
    If the name of the target does not specify an extension, the search will try both .EXE and .DLL.

    The search cannot find modules (.DLLs) loaded dynamically.

    TODO: The search currently does not detect managed dependencies.

    .PARAMETER FilePath
    The full path or file name of the PE.

    .PARAMETER AsShim
    Assume that the executable has been created with shimgen (common for programs installed with chocolatey).
    With this option, it will recover the proper name of the file and search based on that.

    .PARAMETER ShallowDependencies
    Search only direct dependencies.

    .PARAMETER Depth
    Limit the search to the specified depth. Useful for reducing the search time, and avoiding bogus dependencies.

    .PARAMETER ShowMissingOnly
    Show only the names of the missing dependencies.

    .EXAMPLE
    PS C:> Get-PEDependencies notepad

    .EXAMPLE
    PS C:> Get-PEDependencies -FilePath notepad -ShowMissingOnly

    .EXAMPLE
    PS C:> Get-PEDependencies -FilePath explorer -ShallowDependencies

    .EXAMPLE
    PS C:> Get-PEDependencies -FilePath cmd -Depth 2

    .NOTES
    TODO: Search also for managed dependencies.
    #>

    [CmdletBinding(DefaultParametersetName="NoSearchLimit")]
    param(
        [Parameter(Position=1)]
        [ValidateNotNullOrEmpty()]
        [string]$FilePath,

        [switch]$AsShim,

        [Parameter(ParameterSetName='ShallowDependencies')]
        [switch]$ShallowDependencies,

        [Parameter(ParameterSetName='ScopedDependencies')]
        [Int]$Depth,

        [switch]$ShowMissingOnly
    )

    $OriginalFilePath = $FilePath

    [string[]]$paths = $Env:Path.Split(';', [StringSplitOptions]::RemoveEmptyEntries) | `
                       ForEach-Object -Process {
                           if ($_.Contains('%')) {
                               [Environment]::ExpandEnvironmentVariables($_)
                           } else {
                               $_
                           }
                       }

    $paths = @( $pwd.ProviderPath ) + $paths

    #
    # First try to find the proper name to search for
    #
    function CheckPath {
        [CmdletBinding()]
        param(
            [ValidateNotNullOrEmpty()]
            [string]$Name,

            [ValidateSet('Empty', 'EXE', 'DLL')]
            [string]$Extension
        )

        switch ($Extension) {
            'Empty' { $n = $Name }
            'EXE'   { $n = "{0}.exe" -f $Name }
            'DLL'   { $n = "{0}.dll" -f $Name }
            Default { $n = $Name }
        }

        $found = Test-Path -Path $n -PathType Leaf
        if ($found) {
            return $n
        } else {
            return $null
        }
    }

    $doNotTestExtensions = $FilePath.EndsWith(".exe", [StringComparison]::OrdinalIgnoreCase) -or `
                           $FilePath.EndsWith(".dll", [StringComparison]::OrdinalIgnoreCase)

    $n = CheckPath -Name $FilePath -Extension Empty
    if (($n -eq $null) -and (-not $doNotTestExtensions)) {
        $n = CheckPath -Name $FilePath -Extension EXE
        if ($n -eq $null) {
            $n = CheckPath -Name $FilePath -Extension DLL
        }

        if ($n -ne $null) {
            Write-Warning -Message "Searching as $n"
            $FilePath = $n
        }
    }

    if ($n -eq $null) {
        foreach ($path in $paths) {
            $newName = Join-Path -Path $path -ChildPath $FilePath
            $n = CheckPath -Name $newName -Extension Empty
            if ($n -ne $null) {
                Write-Verbose -Message "Found '$FilePath' in '$path'"
                $FilePath = $n
                break
            }

            if ($doNotTestExtensions) {
                continue
            }

            $n = CheckPath -Name $newName -Extension EXE
            if ($n -ne $null) {
                Write-Verbose -Message "Found '$FilePath' as '$n'"
                $FilePath = $n
                break
            }

            $n = CheckPath -Name $newName -Extension DLL
            if ($n -ne $null) {
                Write-Verbose -Message "Found '$FilePath' as '$n'"
                $FilePath = $n
                break
            }
        }
    }

    if ($n -eq $null) {
        Write-Error -Message "Cannot find '$FilePath'"
        return
    }
    $FilePath = $n # not really needed, but this is the invariant we want to maintain

    #
    # If generated from ShimGen, get real target
    #
    if ($AsShim) {
        $shim = Get-ShimProperties -ProgramName $FilePath
        if ($shim -eq $null) {
            Write-Error -Message "It does not appear to be a shim"
            return
        }
        $FilePath = $shim.Path

        if (-not (Test-Path -Path $FilePath -PathType Leaf)) {
            Write-Error -Message "Cannot find target of '$FilePath'"
            return
        }

        Write-Warning -Message "Searching for properties of target file instead: '$FilePath'"
    }

    #
    # Now Get the dependencies
    #

    $pe = Get-PE -FilePath $FilePath
    if ($pe -eq $null) {
        Write-Error -Message "Cannot parse the PE header of '$FilePath'"
        return
    }

    $IsDotNet = $false

    [string[]]$missing = @()
    [string[]]$existing = @()

    [string[]]$modules = $pe.Imports.ModuleName
    $modules = $modules | Sort-Object -Unique

    $visited = New-Object -Type 'System.Collections.Generic.Dictionary[string,ModuleLocationInfo]'
    $queue = New-Object -Type 'System.Collections.Generic.Stack[string]' -ArgumentList @(,$modules)

    foreach ($module in $modules) {
        $m = [ModuleLocationInfo]::new($module, 1, $OriginalFilePath)
        $m.ModuleType = [ModuleTypeGuess]::Native
        $visited.Add($module, $m)
    }

    $processed = 0
    while ($queue.Count -gt 0) {
        $percent = (100.0 * $processed / ($processed + $queue.Count))
        $module = $queue.Pop()

        Write-Progress -Activity "Finding dependencies" -Status "Examining: $module" -PercentComplete $percent
        $processed += 1

        Write-Debug -Message "Examining Module: $module"
        if ($module -eq "mscoree.dll") {
            Write-Debug -Message "This is .NET PE"
            Write-Warning -Message "Reading inside managed PEs not implemented yet"
            $IsDotNet = $true
        }

        if (Test-Path -Path $module) {
            $modulePath = $module
        } else {
            $modulePath = $null
            foreach ($path in $paths) {
                $modulePathCandidate = Join-Path -Path $path -ChildPath $module
                if (Test-Path -Path $modulePathCandidate -PathType Leaf) {
                    $modulePath = $modulePathCandidate
                    break
                }
            }
        }

        if ($modulePath -eq $null) {
            if ($module.StartsWith("api-ms-win-", [StringComparison]::OrdinalIgnoreCase)) {
                Write-Debug -Message "Cannot find module $module"
            } else {
                Write-Warning -Message "Cannot find module $module"
            }

            if ($ShowMissingOnly) {
                Write-Output $module
            } else {
                $missing += $module
            }
            continue
        } else {
            $existing += $module
        }

        $prevm = $visited[$module]
        $prevm.Location = $modulePath

        if ($ShallowDependencies -or (($Depth -gt 0) -and ($prevm.Distance -ge $Depth))) {
            continue
        }

        $modulePe = Get-PE -FilePath $modulePath
        if ($modulePe -eq $null) {
            Write-Error -Message "Cannot retrieve PE properties of module '$module' ($modulePath)"
            continue
        }

        if ($modulePe.Imports -eq $null) {
            if ( $module.StartsWith("api-ms-win-", [StringComparison]::OrdinalIgnoreCase) -or
                 ("ntdll.dll","win32u.dll" -contains $module) )
            {
                Write-Debug -Message "Empty imports for $modulePath"
            } else {
                Write-Verbose -Message "Empty imports for $modulePath"
            }
            continue
        }

        [string[]]$subModules = $modulePe.Imports.ModuleName
        foreach ($subModule in $subModules) {
            if ($visited.ContainsKey($subModule)) {
                $smr = $visited[$subModule]
                $smr.Count += 1
                continue
            }
            Write-Debug -Message "Found submodule: $subModule"
            $queue.Push($subModule) | Out-Null

            $m = [ModuleLocationInfo]::new($subModule, $prevm.Distance + 1, $module)
            $m.ModuleType = [ModuleTypeGuess]::Native
            $visited.Add($subModule, $m) | Out-Null
        }
    }

    #
    # TODO: Enumerate Managed Dependencies
    #

    #
    # Create output
    #

    if ($ShowMissingOnly) {
        # Do nothing: we output as we discover
    } else {
        [PSCustomObject]@{
            # E = $existing
            # M = $missing
            # V = $visited
            Existing = ($existing | ForEach-Object -Process { $visited[$_] })
            Missing = ($missing | ForEach-Object -Process { $visited[$_] })
        }
    }
}