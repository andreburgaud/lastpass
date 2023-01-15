#!/usr/bin/env pwsh

# analyze-lastpass-vault.ps1 is derived from https://github.com/FuLoRi/Analyze-LastPassVaultGUI
# released under the GPL-3.0 License

# Copyright (C) 2023 Andre Burgaud

# This program is free software: you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation, either version 3 of the License, or
# (at your option) any later version.

# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.

# You should have received a copy of the GNU General Public License
# along with this program.  If not, see <https://www.gnu.org/licenses/>.

<#
.SYNOPSIS
Parses a LastPass Vault in XML format. Export the result into a selected format, CSV, HTML, or JSON, or to
a table if no output file is given as a parameter.

.DESCRIPTION
Parses a LastPass Vault in XML format. Export the result into a selected format, CSV, HTML, or JSON, or to
a table if no output file is given as a parameter. In the latter scenario the result is generated to
standard out, whereas when a file is provided as an option, the result is written to the file in the format
corresponding to the extension of the file.

Examples:
> analyze-lastpass-vault.ps1 -Vault my_vault.xml                             # Output a table to stdout
> analyze-lastpass-vault.ps1 -Vault my_vault.xml -OutFile my_vault.csv       # Generate a CSV file
> analyze-lastpass-vault.ps1 -Vault my_vault.xml -OutFile my_vault.json      # Generate a JSON file
> analyze-lastpass-vault.ps1 -Vault my_vault.xml -OutFile my_vault.html      # Generate an HTML file
> analyze-lastpass-vault.ps1 -Vault my_vault.xml -OutFile my_vault.csv -All  # Include most the fields
#>

[CmdletBinding(DefaultParametersetName="vault")]
Param(
  [Parameter(Mandatory,ParameterSetName="vault")]
  [String]$Vault,
  [String]$OutFile,
  [Switch]$All,
  [Parameter(Mandatory,ParameterSetName="version")]
  [switch]$Version,
  [Parameter(Mandatory,ParameterSetName="license")]
  [switch]$License
)

$formats = "html","csv", "json"
$format = "table"

if ($OutFile) {
    $ext = $OutFile.Split(".")[-1].ToLower()
    if ($ext -notin $formats) {
        Write-Host "Extension ${ext} is not supported" -ForeGroundColor Red
        Exit 1
    }
    $format = $ext
}

Set-Variable VersionNumber -Option Constant -Value "0.2.0"
Set-Variable MaxURLLength -Option Constant -Value 50
Write-Host "Analyze LastPass Vault (CLI) version ${VersionNumber}" -ForeGroundColor Green
if ($Version) {
    Exit 0
}

if ($License) {
    $LicenseText = @'
Copyright (C) 2023  Andre Burgaud

This program is free software: you can redistribute it and/or modify
it under the terms of the GNU General Public License as published by
the Free Software Foundation, either version 3 of the License, or
(at your option) any later version.

This program is distributed in the hope that it will be useful,
but WITHOUT ANY WARRANTY; without even the implied warranty of
MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
GNU General Public License for more details.

You should have received a copy of the GNU General Public License
along with this program.  If not, see <https://www.gnu.org/licenses/>.
'@
    Write-Host $LicenseText -ForeGroundColor Yellow
    Exit 0
}

# The vault does not exist
if (-not (Test-Path -Path $Vault -PathType Leaf)) {
    Write-Host "Error: file $Vault does not exist" -ForeGroundColor Red
    Exit 1
}

function UnixTsToDate {
    param([String]$TimeStamp)
    if ($TimeStamp -eq "0") {
        return "0"
    }
    $epoch = Get-Date 01.01.1970
    $epoch + [System.TimeSpan]::FromSeconds($TimeStamp)
}

function HexToString {
    param([String]$HexString)
    -Join($HexString | Select-String ".." -AllMatch | ForEach-Object {$_.Matches} | ForEach-Object {[char]+"0x$_"})
}

function B64ToHEx {
    param([string]$B64String)
    -Join([System.Convert]::FromBase64String($B64String) | ForEach-Object ToString X2)
}

function Get-UserName {
    param([string]$UserName)
    if (-not $Username) {
        return "No UserName"
    }
    $UserName
}

function Get-CipherMode {
    param(
        [String]$Value,
        [String]$Default
    )
    if ($Value) {
        if ($Value.StartsWith("!")) {
            return "CBC"
        } else {
            return "ECB"
        }
    }
    return $Default
}

function Get-Url {
    param(
        [String]$URLHex,
        [Switch]$AllFields
    )
    # Convert the hexadecimal values to text/ASCII
    if (-not [System.Text.RegularExpressions.Regex]::IsMatch($URLHex, '^[0-9a-fA-F]+$')) {
        # String is not a hexadecimal string
        return "ERROR: Invalid hexadecimal string."
    } else {
        $url = HexToString -HexString $URLHex
        if ($AllFields) {
            return $url
        }
        # Return only the first 50 chars of the URL unless -All passed at the command line
        $len = $url.Length
        if ($len -gt $MaxURLLength) {
            $len = $MaxURLLength
        }
        return $url.SubString(0, $len)
    }
}

function Get-IvCt {
    param(
        [String]$EncryptedValue
    )
    $iv, $ct = $EncryptedValue.SubString(1).Split("|")
    return (B64ToHEx -B64String $iv), (B64ToHex -B64String $ct)
}

function OutputCsv {
    param(
        [array]$Records,
        [String]$File,
        [Switch]$AllFields
    )

    if ($AllFields) {
        $Records | Export-Csv -Path $File -NoTypeInformation
    } else {
        $Records |
        Select-Object -Property URL, ID, NameCM, UserNameCM, PasswordCM, ExtraCM, SNote, LastTouch, LastModified |
        Sort-Object -Property URL |
        Export-Csv -Path $File -NoTypeInformation
    }
}

function OutputHtml {
    param(
        [array]$Records,
        [String]$File,
        [Switch]$AllFields
    )
    if ($AllFields) {
        $html = $Records | ConvertTo-Html -Fragment
        $html | Out-File -FilePath $File
    } else {
        $html = $Records |
            Select-Object -Property URL, ID, NameCM, UserNameCM, PasswordCM, ExtraCM, SNote, LastTouch, LastModified |
            Sort-Object -Property URL |
            ConvertTo-Html -Fragment
        $html | Out-File -FilePath $File
    }
}

function OutputJson {
    param(
        [array]$Records,
        [String]$File,
        [Switch]$AllFields
    )
    if ($AllFields) {
        $json = $Records | ConvertTo-Json
        $json | Out-File -FilePath $File
    } else {
        $json = $Records |
            Select-Object -Property URL, ID, NameCM, UserNameCM, PasswordCM, ExtraCM, SNote, LastTouch, LastModified |
            Sort-Object -Property URL |
            ConvertTo-Json
        $json | Out-File -FilePath $File
    }
}


[xml]$xml = Get-Content -Path $Vault

# Initialize an empty array to store the results
$results = @()
$i = 0

# Iterate over the account elements in the XML file
ForEach ($account in $xml.response.accounts.account) {
    # Initialize a new object to store the data for this account
    $i += 1
    if ($i % 10 -eq 0) {
        Write-Host "." -NoNewline -ForeGroundColor Yellow
    }
    $result = [pscustomobject]@{
        Name = $account.name
        NameCM = Get-CipherMode -Value $account.name -Default "No Name"
        URLHex = $account.url
        URL = Get-Url -URLHex $account.url -AllFields:$All
        SNote = $account.sn
        ID = $account.id
        Group = $account.group
        GroupCM = Get-CipherMode -Value $account.group -Default "No Group"
        GroupIVHex = ""
        GroupCTHex = ""
        Extra = $account.extra
        ExtraCM = Get-CipherMode -Value $account.extra -Default "No Extra"
        IsBookmark = $account.isbookmark
        NeverAutofill = $account.never_autofill
        # Unix Timestamp
        LastTouchTs = $account.last_touch
        LastTouch = UnixTsToDate -TimeStamp $account.last_touch
        # Unix Timestamp
        LastModifiedTs = $account.last_modified
        LastModified = UnixTsToDate -TimeStamp $account.last_modified
        LaunchCount = $account.launch_count
        UserName = Get-UserName -UserName $account.login.u
        UserNameCM = Get-CipherMode -Value $account.login.u -Default "No UserName"
        UserNameIVHex = ""
        UserNameCTHex = ""
        Password = $account.login.p
        PasswordCM = Get-CipherMode -Value $account.login.p -Default "No Password"
        PasswordIVHex = ""
        PasswordCTHex = ""
    }

    if ($result.UserNameCM -eq "CBC") {
        $result.UserNameIVHex, $result.UserNameCTHex = Get-IvCt -EncryptedValue $account.login.u
    }

    if ($result.PasswordCM -eq "CBC") {
        $result.PasswordIVHex, $result.PasswordCTHex = Get-IvCt -EncryptedValue $account.login.p
    }

    if ($result.GroupCM -eq "CBC") {
        $result.GroupIVHex, $result.GroupCTHex = Get-IvCt -EncryptedValue $account.group
    }

    # Add the result object to the array
    $results += $result
}

# Terminate the progress dots
Write-Host

switch($format) {
    "csv" {
        OutputCsv -Records $results -File $Outfile -AllFields:$All
    }
    "html" {
        OutputHtml -Records $results -File $Outfile -AllFields:$All
    }
    "json" {
        OutputJson -Records $results -File $Outfile -AllFields:$All
    }
    Default {
        Write-Output (
            $results | Sort-Object -Property URL |
            Format-Table URL, ID, NameCM, UserNameCM, PasswordCM, ExtraCM, SNote, LastTouch, LastModified
        )
    }
}
