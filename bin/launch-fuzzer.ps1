# Launcher for fuzz.py — pops up file pickers so you don't need the command line.
# Started by the "LMS Fuzzer" desktop shortcut.
Add-Type -AssemblyName System.Windows.Forms
$here = Split-Path -Parent $MyInvocation.MyCommand.Path   # the bin\ folder
$root = Split-Path -Parent $here                          # project root
$reqDir = Join-Path $root 'Requests'
$payDir = Join-Path $root 'payloads'

function Pick-File($title, $filter, $initial) {
    $dlg = New-Object System.Windows.Forms.OpenFileDialog
    $dlg.Title = $title
    $dlg.Filter = $filter
    $dlg.InitialDirectory = $initial
    if ($dlg.ShowDialog() -ne [System.Windows.Forms.DialogResult]::OK) { return $null }
    return $dlg.FileName
}

# Yes/No prompt with a default applied when the user just presses Enter.
# $default is 'y' or 'n'; the capital letter in the prompt shows which.
function Ask-YesNo($question, $default) {
    $hint = if ($default -eq 'y') { '(Y/n)' } else { '(y/N)' }
    $ans = Read-Host "$question $hint"
    if ([string]::IsNullOrWhiteSpace($ans)) { $ans = $default }
    return ($ans -match '^(y|Y)')
}

Write-Host "=== LMS Fuzzer ===" -ForegroundColor Cyan
Write-Host "Authorized testing only. Pick your Burp raw request file (must contain the word FUZZ)."

$req = Pick-File "Select a Burp raw request (FUZZ) OR a Postman collection (*.json)" "Requests (*.txt;*.req;*.json)|*.txt;*.req;*.json|All files (*.*)|*.*" $reqDir
if (-not $req) { Write-Host "Cancelled." ; Read-Host "Press Enter to close"; exit }

$isPostman = $req.ToLower().EndsWith(".json")
$env = ""; $token = ""
if ($isPostman) {
    Write-Host "Postman collection selected. You'll pick the request and field in a moment." -ForegroundColor Yellow
    $token = Read-Host "Bearer token value (for {{token}}), or blank to skip"
    if (Ask-YesNo "Do you have a Postman environment .json to load?" 'n') {
        $env = Pick-File "Select the Postman environment export" "JSON (*.json)|*.json|All files (*.*)|*.*" $reqDir
    }
}

$pay = Pick-File "Select the payload list (one per line)" "Text files (*.txt)|*.txt|All files (*.*)|*.*" $payDir
if (-not $pay) { Write-Host "Cancelled." ; Read-Host "Press Enter to close"; exit }

$scheme = Read-Host "Scheme [https]"
if ([string]::IsNullOrWhiteSpace($scheme)) { $scheme = "https" }

$delay = Read-Host "Delay between requests in seconds [0.3]"
if ([string]::IsNullOrWhiteSpace($delay)) { $delay = "0.3" }

# Defaults chosen for the usual run: baseline on, save bodies on, real cert, live (no dry run).
$doBase = Ask-YesNo "Send a baseline request and flag differences?" 'y'
$doBody = Ask-YesNo "Save full response bodies to a folder?" 'y'
$doIns  = Ask-YesNo "Skip TLS certificate check (self-signed test env)?" 'n'
$doDry  = Ask-YesNo "Dry run first (print requests, send nothing)?" 'n'

$pyArgs = @("$here\fuzz.py", "--request", $req, "--payloads", $pay, "--scheme", $scheme, "--delay", $delay)
if ($env)   { $pyArgs += @("--env", $env) }
if ($token) { $pyArgs += @("--var", "token=$token") }
if ($doBase) { $pyArgs += "--baseline" }
if ($doBody) { $pyArgs += "--save-bodies" }
if ($doIns)  { $pyArgs += "--insecure" }
if ($doDry)  { $pyArgs += "--dry-run" }

Write-Host "`nRunning: python $($pyArgs -join ' ')`n" -ForegroundColor DarkGray
& python @pyArgs

Write-Host ""
Read-Host "Done. Press Enter to close"
