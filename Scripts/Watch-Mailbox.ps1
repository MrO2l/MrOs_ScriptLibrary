<# 
.SYNOPSIS
  Prüft, ob in einer Mailbox ungelesene E-Mails älter als N Minuten sind.
  Verbindet sich app-only via App Registration (Zertifikat) mit Exchange Online
  (Validierungs-Login) sowie Microsoft Graph (Nachrichtenlesen).

.OUTPUTS
  [bool] True  -> Es existiert mind. 1 ungelesene E-Mail älter als MaxAgeMinutes.
         False -> Keine ungelesene E-Mail älter als MaxAgeMinutes ODER Fehler (siehe $ErrorMessage).

.NOTES
  Erforderliche Berechtigungen (App Permissions in Entra ID):
    - Microsoft Graph: Mail.ReadBasic.All (reicht für Absender/Betreff/ReceivedDate) 
      oder Mail.Read (wenn Body o.ä. nötig wäre)
    - Admin-Consent erforderlich.
  Zertifikat muss im Zertifikatsspeicher vorhanden sein (bei Verwendung von Thumbprint).

#>

[CmdletBinding()]
param(
    # Tenant (GUID oder verified domain / <tenant>.onmicrosoft.com für ExO)
    [Parameter(Mandatory=$true)]
    [string]$TenantId,

    # Für Connect-ExchangeOnline: Ihre Organization (z.B. contoso.onmicrosoft.com)
    [Parameter(Mandatory=$true)]
    [string]$Organization,

    # App Registration (Client) ID
    [Parameter(Mandatory=$true)]
    [string]$AppId,

    # ENTWEDER: Zertifikat-Thumbprint im CurrentUser\My (empfohlen auf Admin-Workstations/Runbooks)
    [Parameter(Mandatory=$false)]
    [string]$CertificateThumbprint,

    # ODER: Pfad zu einer PFX/PEM-Datei (inkl. privatem Schlüssel)
    [Parameter(Mandatory=$false)]
    [string]$CertificatePath,

    # Optional: Passwort für PFX
    [Parameter(Mandatory=$false)]
    [SecureString]$CertificatePassword,

    # Zu prüfende Mailbox (UPN oder GUID)
    [Parameter(Mandatory=$true)]
    [string]$Mailbox,

    # Minuten-Schwelle (älter = True)
    [Parameter(Mandatory=$false)]
    [int]$MaxAgeMinutes = 10,

    # Max. wie viele ungelesene Nachrichten sollen geprüft werden (Performance)
    [Parameter(Mandatory=$false)]
    [int]$TopToCheck = 200,

    # Zu untersuchender Ordner (Standard: Inbox). Well-known-Folder-Name gemäß Graph.
    [Parameter(Mandatory=$false)]
    [ValidateSet("Inbox","Drafts","SentItems","DeletedItems","Archive","JunkEmail","Outbox")]
    [string]$Folder = "Inbox"
)

# Globale/äußere Fehler-Variable (vom Nutzer gewünscht)
$script:ErrorMessage = $null

# Ausgabe-Variable (boolean)
$HasUnreadOlderThanThreshold = $false

function Write-VerboseOrHost($msg) {
    if ($PSBoundParameters.ContainsKey('Verbose')) { Write-Verbose $msg } else { Write-Host $msg }
}

try {
    # --- Modul-Prüfungen ---
    $exoModule = Get-Module -ListAvailable -Name ExchangeOnlineManagement | Select-Object -First 1
    if (-not $exoModule) {
        throw "Benötigtes Modul 'ExchangeOnlineManagement' ist nicht installiert. Installieren Sie es mit: Install-Module ExchangeOnlineManagement -Scope AllUsers"
    }

    $mgModule = Get-Module -ListAvailable -Name Microsoft.Graph | Select-Object -First 1
    if (-not $mgModule) {
        throw "Benötigtes Modul 'Microsoft.Graph' ist nicht installiert. Installieren Sie es mit: Install-Module Microsoft.Graph -Scope AllUsers"
    }

    Import-Module ExchangeOnlineManagement -ErrorAction Stop
    Import-Module Microsoft.Graph -ErrorAction Stop

    # --- Zertifikat laden ---
    $cert = $null
    if ($CertificateThumbprint) {
        $certPath = "Cert:\CurrentUser\My\$CertificateThumbprint"
        if (-not (Test-Path $certPath)) {
            throw "Zertifikat mit Thumbprint '$CertificateThumbprint' wurde im Speicher CurrentUser\My nicht gefunden."
        }
        $cert = Get-Item $certPath
    }
    elseif ($CertificatePath) {
        if (-not (Test-Path $CertificatePath)) {
            throw "Zertifikat-Datei '$CertificatePath' wurde nicht gefunden."
        }
        if ($CertificatePassword) {
            $cert = New-Object System.Security.Cryptography.X509Certificates.X509Certificate2($CertificatePath, $CertificatePassword)
        } else {
            # Versucht ohne Passwort zu laden (z.B. PEM mit unverschlüsseltem Key)
            $cert = New-Object System.Security.Cryptography.X509Certificates.X509Certificate2($CertificatePath)
        }
    }
    else {
        throw "Bitte geben Sie entweder -CertificateThumbprint oder -CertificatePath an."
    }

    # --- 1) Exchange Online: App-Only Connect (Validierung der App/Org) ---
    Write-VerboseOrHost "Verbinde mit Exchange Online (App-Only)…"
    Connect-ExchangeOnline `
        -AppId $AppId `
        -Organization $Organization `
        -Certificate $cert `
        -ShowBanner:$false `
        -ErrorAction Stop

    # Einfache Validierung der Mailbox-Existenz/Erreichbarkeit (ohne Itemzugriff):
    try {
        $null = Get-EXOMailbox -Identity $Mailbox -ErrorAction Stop
        Write-VerboseOrHost "Mailbox '$Mailbox' gefunden."
    }
    catch {
        throw "Mailbox '$Mailbox' konnte nicht gelesen werden: $($_.Exception.Message)"
    }

    # --- 2) Microsoft Graph: App-Only Connect (für Nachrichten) ---
    Write-VerboseOrHost "Verbinde mit Microsoft Graph (App-Only)…"
    # Für Mail-Lesen reicht dieser Scope in App-Only-Kontext (App Permissions): 
    # Scope-Parameter wird in App-Only ignoriert, aber Connect ist erforderlich.
    Connect-MgGraph -TenantId $TenantId -ClientId $AppId -Certificate $cert -NoWelcome -ErrorAction Stop

    # Sicherstellen, dass die benötigte API geladen ist
    Select-MgProfile -Name "beta" | Out-Null
    # (Für Stabilität kann auch v1.0 genutzt werden, hier reicht v1.0.)
    Select-MgProfile -Name "v1.0" | Out-Null

    # --- Nachrichten abrufen (ungelesen) ---
    # Hinweis: Wir filtern nach isRead eq false im gewünschten Ordner.
    # Erst Ordner-ID ermitteln (well-known name per Graph):
    $inbox = Get-MgUserMailFolder -UserId $Mailbox -Filter "displayName eq '$Folder'" -ErrorAction SilentlyContinue | Select-Object -First 1
    if (-not $inbox) {
        # Fallback auf well-known-id "inbox" etc.
        $wellKnownId = $Folder.ToLower()
        $inbox = Get-MgUserMailFolder -UserId $Mailbox -MailFolderId $wellKnownId -ErrorAction Stop
    }

    # Ungelesene Mails aus dem Ordner abrufen (Top limitierbar)
    # Graph Filter: isRead eq false
    $messages = Get-MgUserMailFolderMessage `
        -UserId $Mailbox `
        -MailFolderId $inbox.Id `
        -Filter "isRead eq false" `
        -OrderBy "receivedDateTime desc" `
        -Top $TopToCheck `
        -ErrorAction Stop

    $unreadCount = ($messages | Measure-Object).Count
    Write-VerboseOrHost "Ungelesene Nachrichten gefunden: $unreadCount (geprüft werden bis zu $TopToCheck)."

    if ($unreadCount -gt 0) {
        $nowUtc = (Get-Date).ToUniversalTime()
        foreach ($msg in $messages) {
            # receivedDateTime ist UTC (ISO 8601)
            $received = Get-Date $msg.receivedDateTime
            $ageMinutes = [math]::Round(($nowUtc - $received.ToUniversalTime()).TotalMinutes, 2)
            if ($ageMinutes -ge $MaxAgeMinutes) {
                $HasUnreadOlderThanThreshold = $true
                break
            }
        }
    }

}
catch {
    $script:ErrorMessage = $_.Exception.Message
    # Im Fehlerfall geben wir False zurück (wie gewünscht) und haben Details in $ErrorMessage
    $HasUnreadOlderThanThreshold = $false
}
finally {
    # Aufräumen der Sitzungen (best-effort)
    try { Disconnect-ExchangeOnline -Confirm:$false -ErrorAction SilentlyContinue | Out-Null } catch {}
    try { Disconnect-MgGraph -ErrorAction SilentlyContinue | Out-Null } catch {}
}

# Boolesches Ergebnis ausgeben
$HasUnreadOlderThanThreshold

# Zusätzlich: Error-Details im gewünschten Variablennamen bereitstellen
# (Variable ist bereits gesetzt; optional kann man sie hier auch explizit ausgeben)
# Write-Output $script:ErrorMessage
