#Requires -Module Environment

#function Check-PEDependencies {
    [CmdletBinding()]
    param(
        [ValidateNotNullOrEmpty()]
        [string]$FilePath,

        [switch]$AsShim,

        [switch]$ShallowDependencies,

        [switch]$ShowMissingOnly
    )

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

    $visited = New-Object -Type 'System.Collections.Generic.HashSet[string]' -ArgumentList @(,$modules)
    $queue = New-Object -Type 'System.Collections.Generic.Stack[string]' -ArgumentList @(,$modules)

    while ($queue.Count -gt 0) {
        $module = $queue.Pop()

        Write-Debug -Message "Examining Module: $module"
        if ($module -eq "mscoree.dll") {
            Write-Verbose -Message "This is .NET PE"
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

            $missing += $module
            continue
        } else {
            $existing += $modulePath
        }

        if ($ShallowDependencies) {
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
            if ($visited.Contains($subModule)) {
                continue
            }
            Write-Debug -Message "Found submodule: $subModule"
            $queue.Push($subModule) | Out-Null
            $visited.Add($subModule) | Out-Null
        }
    }

    if ($ShowMissingOnly) {
        $missing
    } else {
        [PSCustomObject]@{
            Existing = $existing
            Missing = $missing
        }
    }
#}