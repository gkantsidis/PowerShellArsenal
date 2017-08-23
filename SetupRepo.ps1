#Requires -Version 3

[CmdletBinding()]
param(
)

if ((git remote) -notcontains "official") {
    Write-Verbose -Message "Creating remote for official depot"
    git remote add --tags official https://github.com/mattifestation/PowerShellArsenal.git
    git fetch official
}

if ((git remote) -notcontains "lowleveldesign") {
    Write-Verbose -Message "Creating remote for lowleveldesign fork"
    git remote add --tags lowleveldesign https://github.com/lowleveldesign/PowerShellArsenal.git
    git fetch lowleveldesign
}