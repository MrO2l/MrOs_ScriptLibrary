<# 
.SYNOPSIS
  Analysiert eine E-Mail-Header-Textdatei und gibt relevante Informationen aus.

.PARAMETER Path
  Pfad zur Textdatei mit dem kompletten E-Mail-Header.

.EXAMPLE
  .\Parse-MailHeader.ps1 -Path ".\header.txt"

.NOTES
  - Unterstützt „gefaltete“ Header (Zeilen, die mit Leerzeichen/Tab beginnen).
  - Zeigt u.a. From/To/Subject/Date/Message-ID, Return-Path, Received-Kette,
    IPs, Authentication-Results (SPF/DKIM/DMARC), Received-SPF, ARC, X-Header.
#>

[CmdletBinding()]
param(
  [Parameter(Mandatory=$true, Position=0)]
  [ValidateScript({ Test-Path $_ -PathType Leaf })]
  [string]$Path
)

function Unfold-Headers {
  param([string]$Raw)

  # Normiere Zeilenenden, splitte in Zeilen
  $lines = $Raw -replace "`r`n", "`n" -replace "`r", "`n" -split "`n"

  # Entfalte: Folgezeilen, die mit Space/Tab beginnen, an die vorherige Zeile anhängen
  $unfolded = New-Object System.Collections.Generic.List[string]
  foreach ($line in $lines) {
    if ($line -match '^\s') {
      if ($unfolded.Count -gt 0) {
        $last = $unfolded[$unfolded.Count-1]
        $unfolded[$unfolded.Count-1] = $last + ' ' + ($line.Trim())
      }
    } else {
      # Stoppe an erster Leerzeile (Beginn Body); Header sind davor
      if ($line -eq '') { break }
      $unfolded.Add($line)
    }
  }
  return $unfolded
}

function Parse-Headers {
  param([string[]]$Lines)

  # Dictionary: key -> List<string> (da Header mehrfach vorkommen können)
  $dict = @{}
  foreach ($l in $Lines) {
    $idx = $l.IndexOf(':')
    if ($idx -gt 0) {
      $name = $l.Substring(0,$idx).Trim()
      $val  = $l.Substring($idx+1).Trim()
      $key  = $name.ToLowerInvariant()
      if (-not $dict.ContainsKey($key)) { $dict[$key] = New-Object System.Collections.Generic.List[string] }
      $dict[$key].Add($val)
    }
  }
  return $dict
}

function Try-Parse-Date {
  param([string]$s)
  # Versuche Date/DateTimeOffset tolerant zu parsen (RFC2822-ähnlich)
  try {
    $dto = [System.DateTimeOffset]::Parse($s, [System.Globalization.CultureInfo]::InvariantCulture, [System.Globalization.DateTimeStyles]::AllowWhiteSpaces)
    return $dto
  } catch {
    # Häufig: Semikolon-getrenntes Datum am Ende einer Received-Zeile => nimm Teil nach letztem ';'
    if ($s -match '.*;\s*(.+)$') {
      $tail = $Matches[1]
      try {
        $dto = [System.DateTimeOffset]::Parse($tail, [System.Globalization.CultureInfo]::InvariantCulture, [System.Globalization.DateTimeStyles]::AllowWhiteSpaces)
        return $dto
      } catch { return $null }
    }
    return $null
  }
}

function Extract-IPs {
  param([string]$text)
  $ipv4 = [regex]'\b(?:(?:25[0-5]|2[0-4]\d|1?\d?\d)(?:\.|$)){4}\b'
  $ipv6 = [regex]'(?i)\b(?:[0-9a-f]{1,4}:){2,7}[0-9a-f]{1,4}\b'
  $ips = [System.Collections.Generic.HashSet[string]]::new()
  foreach ($m in $ipv4.Matches($text)) { $null = $ips.Add($m.Value) }
  foreach ($m in $ipv6.Matches($text)) { $null = $ips.Add($m.Value) }
  return $ips.ToArray()
}

function Trunc {
  param([string]$s, [int]$len=80)
  if ([string]::IsNullOrEmpty($s)) { return $s }
  if ($s.Length -le $len) { return $s }
  return $s.Substring(0,$len) + '…'
}

# ------------------ Hauptlogik ------------------

$raw = Get-Content -Path $Path -Raw -ErrorAction Stop
$unfolded = Unfold-Headers -Raw $raw
$headers = Parse-Headers -Lines $unfolded

# Helfer zum Holen eines Felds (erstes Vorkommen)
function H1($name) {
  $k = $name.ToLowerInvariant()
  if ($headers.ContainsKey($k) -and $headers[$k].Count -gt 0) { return $headers[$k][0] }
  return $null
}

# Basisdaten
$from        = H1 'From'
$to          = H1 'To'
$subject     = H1 'Subject'
$dateRaw     = H1 'Date'
$dateParsed  = if ($dateRaw) { Try-Parse-Date $dateRaw } else { $null }
$msgid       = H1 'Message-ID'
$returnPath  = H1 'Return-Path'
$replyTo     = H1 'Reply-To'
$mime        = H1 'MIME-Version'

# Auth / Sicherheit
$authResults = if ($headers.ContainsKey('authentication-results')) { $headers['authentication-results'] } else { @() }
$receivedSPF = if ($headers.ContainsKey('received-spf')) { $headers['received-spf'] } else { @() }
$dkimSig     = if ($headers.ContainsKey('dkim-signature')) { $headers['dkim-signature'] } else { @() }
$dmarc       = if ($headers.ContainsKey('dmarc-filter')) { $headers['dmarc-filter'] } else { @() }
$arcRes      = if ($headers.ContainsKey('arc-authentication-results')) { $headers['arc-authentication-results'] } else { @() }
$arcSeal     = if ($headers.ContainsKey('arc-seal')) { $headers['arc-seal'] } else { @() }

# Received-Kette (mehrfach)
$received = if ($headers.ContainsKey('received')) { $headers['received'] } else { @() }

# Alle IPs sammeln
$allText = ($unfolded -join "`n")
$ips = Extract-IPs -text $allText

# Hops mit Timestamps extrahieren (Versuch)
$hops = @()
for ($i=0; $i -lt $received.Count; $i++) {
  $r = $received[$i]
  $ts = Try-Parse-Date $r
  # Extract primitive "from ... by ..." falls vorhanden
  $fromM = [regex]::Match($r, '(?i)\bfrom\s+(.+?)\s+(?=by\b|with\b|id\b|;|$)')
  $byM   = [regex]::Match($r, '(?i)\bby\s+(.+?)\s+(?=with\b|id\b|;|$)')
  $heloM = [regex]::Match($r, '(?i)\bhelo\s*=\s*([^\s;]+)')
  $tlsM  = [regex]::Match($r, '(?i)\b(using|with)\s+tls[^\s;]*')
  $obj = [PSCustomObject]@{
    Index        = $i  # 0 = letzte „Received“-Zeile im Header (i.d.R. am Ziel nah), höhere Indizes = frühere Hops
    From         = if ($fromM.Success) { $fromM.Groups[1].Value } else { $null }
    By           = if ($byM.Success)   { $byM.Groups[1].Value }   else { $null }
    HELO         = if ($heloM.Success) { $heloM.Groups[1].Value } else { $null }
    TLS          = if ($tlsM.Success)  { $tlsM.Value }            else { $null }
    Date         = $ts
    Raw          = $r
  }
  $hops += $obj
}

# Hop-Deltas (nur wenn Datum vorhanden, sortiere chronologisch)
$hopsChrono = $hops | Sort-Object { if ($_.Date) { $_.Date } else { [datetimeoffset]::MinValue } }
for ($i=1; $i -lt $hopsChrono.Count; $i++) {
  $prev = $hopsChrono[$i-1]
  $curr = $hopsChrono[$i]
  if ($prev.Date -and $curr.Date) {
    $curr | Add-Member -NotePropertyName HopDelay -NotePropertyValue ($curr.Date - $prev.Date) -Force
  }
}

# ------------------ Ausgabe ------------------

Write-Host "=== E-Mail Header Analyse ===" -ForegroundColor Cyan

Write-Host "`n[Allgemein]" -ForegroundColor Yellow
if ($from)       { Write-Host ("Von:        {0}" -f $from) }
if ($to)         { Write-Host ("An:         {0}" -f $to) }
if ($subject)    { Write-Host ("Betreff:    {0}" -f $subject) }
if ($dateRaw)    { Write-Host ("Datum:      {0}" -f $dateRaw) }
if ($dateParsed) { Write-Host ("(Parsed):   {0:u} (UTC)" -f $dateParsed.UtcDateTime) }
if ($msgid)      { Write-Host ("Message-ID: {0}" -f $msgid) }
if ($returnPath) { Write-Host ("Return-Path:{0}" -f $returnPath) }
if ($replyTo)    { Write-Host ("Reply-To:   {0}" -f $replyTo) }
if ($mime)       { Write-Host ("MIME-Ver.:  {0}" -f $mime) }

Write-Host "`n[Sicherheit & Auth]" -ForegroundColor Yellow
if ($authResults.Count -gt 0) {
  Write-Host "Authentication-Results:"
  $authResults | ForEach-Object { "  - " + $_ } | Write-Output
} else {
  Write-Host "Authentication-Results: (keine gefunden)"
}

if ($receivedSPF.Count -gt 0) {
  Write-Host "Received-SPF:"
  $receivedSPF | ForEach-Object { "  - " + $_ } | Write-Output
}

if ($dkimSig.Count -gt 0) {
  Write-Host "DKIM-Signature (gekürzt):"
  foreach ($d in $dkimSig) {
    # gängige DKIM-Tags extrahieren
    $dTag = @{}
    foreach ($tag in 'd','s','a','bh','b') {
      $m = [regex]::Match($d, "(?i)\b$tag=([^;]+)")
      if ($m.Success) { $dTag[$tag] = $m.Groups[1].Value }
    }
    $bShort = if ($dTag.ContainsKey('b')) { Trunc $dTag['b'] 40 } else { $null }
    Write-Host ("  - d={0}; s={1}; a={2}; bh={3}; b={4}" -f $dTag['d'], $dTag['s'], $dTag['a'], (Trunc $dTag['bh'] 24), $bShort)
  }
}

if ($dmarc.Count -gt 0) {
  Write-Host "DMARC/Filter:"
  $dmarc | ForEach-Object { "  - " + $_ } | Write-Output
}

if ($arcRes.Count -gt 0 -or $arcSeal.Count -gt 0) {
  Write-Host "ARC:"
  $arcRes  | ForEach-Object { "  - ARC-Authentication-Results: " + $_ } | Write-Output
  $arcSeal | ForEach-Object { "  - ARC-Seal: " + (Trunc $_ 100) }       | Write-Output
}

Write-Host "`n[Received-Kette]" -ForegroundColor Yellow
if ($received.Count -gt 0) {
  # Originalreihenfolge (wie im Header): neueste zuerst – wir zeigen indexiert
  for ($i=0; $i -lt $received.Count; $i++) {
    $r = $received[$i]
    $ts = Try-Parse-Date $r
    $tsTxt = if ($ts) { " — " + $ts.ToString("u") + " UTC" } else { "" }
    Write-Host ("Hop #{0}: {1}{2}" -f $i, (Trunc $r 180), $tsTxt)
  }

  # Optional: Chronologische Übersicht mit Delays
  if ($hopsChrono.Count -gt 1 -and ($hopsChrono | Where-Object Date)) {
    Write-Host "`n(Hops chronologisch – inkl. Laufzeiten)" -ForegroundColor DarkCyan
    foreach ($h in $hopsChrono) {
      $line = "- " 
      if ($h.Date) { $line += $h.Date.ToString("u") + " UTC: " }
      if ($h.From) { $line += "from " + $h.From + " " }
      if ($h.By)   { $line += "by "   + $h.By   + " " }
      if ($h.HELO) { $line += "(HELO=" + $h.HELO + ") " }
      if ($h.TLS)  { $line += "[" + $h.TLS + "] " }
      if ($h.PSObject.Properties.Match('HopDelay')) {
        $line += " Δ=" + $h.HopDelay.ToString()
      }
      Write-Host $line
    }
  }
} else {
  Write-Host "(keine Received-Header gefunden)"
}

Write-Host "`n[Extrahierte IP-Adressen]" -ForegroundColor Yellow
if ($ips.Count -gt 0) {
  $ips | ForEach-Object { "  - " + $_ } | Write-Output
} else {
  Write-Host "(keine IPs gefunden)"
}

Write-Host "`n[Fertige Felder (weitere häufige X-Header)]" -ForegroundColor Yellow
foreach ($name in @(
  'X-Originating-IP','X-ClientProxiedBy','X-MS-Exchange-Organization-AuthAs',
  'X-MS-Exchange-Organization-Network-Message-Id','X-Google-Smtp-Source',
  'X-SES-Outgoing','List-Id','List-Unsubscribe'
)) {
  $k = $name.ToLowerInvariant()
  if ($headers.ContainsKey($k)) {
    foreach ($v in $headers[$k]) { Write-Host ("{0}: {1}" -f $name, $v) }
  }
}

Write-Host "`n=== Ende ===" -ForegroundColor Cyan
