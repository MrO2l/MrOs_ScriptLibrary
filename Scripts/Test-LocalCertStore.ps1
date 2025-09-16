<# 
.SYNOPSIS
  Prüft lokale Zertifikate auf Gültigkeit/Restlaufzeit.

.DESCRIPTION
  Liest standardmäßig die Stores Cert:\LocalMachine\My und Cert:\CurrentUser\My aus
  und bewertet jedes Zertifikat:
    - NotYetValid   = Noch nicht gültig (immer "nicht gültig")
    - Expired       = Abgelaufen (immer "nicht gültig")
    - ExpiringSoon  = Läuft in <= DaysThreshold Tagen ab ("nicht gültig")
    - Valid         = Gültig (Restlaufzeit > DaysThreshold)

.PARAMETER DaysThreshold
  Anzahl Tage bis zum Ablauf, ab der ein Zertifikat als NICHT GÜLTIG gilt.
  0 = läuft heute ab oder ist bereits abgelaufen.

.PARAMETER Stores
  Liste der zu prüfenden Zertifikatpfade (Cert:\…); Default: LM/My und CU/My.

.PARAMETER ShowAll
  Zeigt alle Zertifikate (nicht nur die als nicht gültig eingestuften).

.EXAMPLE
  .\Check-Certs.ps1 -DaysThreshold 0
  # zeigt Zertifikate, die heute ablaufen/abgelaufen sind oder noch nicht gültig sind

.EXAMPLE
  .\Check-Certs.ps1 -DaysThreshold 14
  # zeigt Zertifikate, die innerhalb der nächsten 14 Tage ablaufen (oder ungültig sind)

.EXAMPLE
  .\Check-Certs.ps1 -DaysThreshold 30 -ShowAll | Out-GridView
  # zeigt alle inkl. Status, in einer GridView
#>

[CmdletBinding()]
param(
    [Parameter(Mandatory = $false)]
    [ValidateRange(0, [int]::MaxValue)]
    [int]$DaysThreshold = 0,

    [Parameter(Mandatory = $false)]
    [string[]]$Stores = @(
        'Cert:\LocalMachine\My',
        'Cert:\CurrentUser\My'
    ),

    [Parameter(Mandatory = $false)]
    [switch]$ShowAll
)

$ErrorActionPreference = 'Stop'
$now = Get-Date

# Ergebnisse einsammeln
$results = foreach ($storePath in $Stores) {
    if (-not (Test-Path -LiteralPath $storePath)) {
        Write-Verbose "Store nicht gefunden: $storePath"
        continue
    }

    # Nur echte Zertifikate (keine Container) holen
    Get-ChildItem -LiteralPath $storePath -ErrorAction SilentlyContinue |
        Where-Object { $_ -is [System.Security.Cryptography.X509Certificates.X509Certificate2] } |
        ForEach-Object {
            $cert = $_

            # Berechnungen
            $daysToExpiry = [math]::Floor(($cert.NotAfter - $now).TotalDays)

            $status = switch ($true) {
                ($now -lt $cert.NotBefore)                              { 'NotYetValid';    break }
                ($cert.NotAfter -lt $now)                               { 'Expired';        break }
                ($cert.NotAfter -le $now.AddDays($DaysThreshold))       { 'ExpiringSoon';   break }
                default                                                 { 'Valid' }
            }

            [pscustomobject]@{
                Store        = $storePath
                Subject      = $cert.Subject
                FriendlyName = $cert.FriendlyName
                Issuer       = $cert.Issuer
                Thumbprint   = $cert.Thumbprint
                NotBefore    = $cert.NotBefore
                NotAfter     = $cert.NotAfter
                DaysToExpiry = $daysToExpiry
                Status       = $status
                IsValid      = ($status -eq 'Valid')
            }
        }
}

if (-not $results) {
    Write-Warning "Keine Zertifikate gefunden in: $($Stores -join ', ')"
    exit 0
}

# Ausgabe: standardmäßig nur die nicht gültigen Zertifikate
$toShow = if ($ShowAll) { $results } else { $results | Where-Object { -not $_.IsValid } }

$toShow |
    Sort-Object -Property NotAfter |
    Format-Table -AutoSize Store, Subject, FriendlyName, Issuer, Thumbprint, NotBefore, NotAfter, DaysToExpiry, Status

# Exit-Code: 0 = alles ok, 2 = es gibt nicht gültige Zertifikate
$notValidCount = ($results | Where-Object { -not $_.IsValid }).Count
if ($notValidCount -gt 0) { exit 2 } else { exit 0 }
