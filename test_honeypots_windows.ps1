# PHIDS Honeypot Testing Script for Windows PowerShell
# This script tests SSH and HTTP honeypots using PowerShell-native commands
# No need for SSH client, curl, or telnet installations

param(
    [switch]$Verbose,
    [switch]$SkipSSH,
    [switch]$SkipHTTP
)

Write-Host "🚨 PHIDS Honeypot Testing Script for Windows" -ForegroundColor Cyan
Write-Host "=" * 60 -ForegroundColor Cyan
Write-Host "🔧 Testing honeypot services using PowerShell commands" -ForegroundColor Yellow
Write-Host "⚠️  Make sure PHIDS is running: python main.py --debug" -ForegroundColor Yellow
Write-Host ""

# Function to test TCP connection
function Test-TCPConnection {
    param(
        [string]$Host,
        [int]$Port,
        [string]$ServiceName
    )
    
    try {
        $client = New-Object System.Net.Sockets.TcpClient
        $client.ReceiveTimeout = 5000
        $client.SendTimeout = 5000
        
        Write-Host "🔍 Testing $ServiceName connection to ${Host}:${Port}..." -ForegroundColor White
        
        $result = $client.BeginConnect($Host, $Port, $null, $null)
        $success = $result.AsyncWaitHandle.WaitOne(5000, $false)
        
        if ($success) {
            $client.EndConnect($result)
            Write-Host "✅ $ServiceName honeypot is accessible on port $Port" -ForegroundColor Green
            
            if ($ServiceName -eq "SSH") {
                # Send SSH banner to trigger logging
                $stream = $client.GetStream()
                $writer = New-Object System.IO.StreamWriter($stream)
                $writer.WriteLine("SSH-2.0-PowerShell-Test-Client")
                $writer.Flush()
                Start-Sleep -Seconds 1
            }
            
            $client.Close()
            return $true
        } else {
            Write-Host "❌ $ServiceName honeypot is not responding on port $Port" -ForegroundColor Red
            $client.Close()
            return $false
        }
    } catch {
        Write-Host "❌ Error testing $ServiceName honeypot: $($_.Exception.Message)" -ForegroundColor Red
        if ($client) { $client.Close() }
        return $false
    }
}

# Function to test HTTP honeypot
function Test-HTTPHoneypot {
    param([string]$BaseUrl)
    
    $testPaths = @(
        "/",
        "/admin", 
        "/login",
        "/config",
        "/wp-admin"
    )
    
    $successCount = 0
    
    foreach ($path in $testPaths) {
        try {
            $url = "$BaseUrl$path"
            Write-Host "🔍 Testing HTTP request: $url" -ForegroundColor White
            
            $response = Invoke-WebRequest -Uri $url -Method GET -TimeoutSec 10 -ErrorAction Stop
            
            if ($response.StatusCode -eq 200) {
                Write-Host "✅ HTTP request successful (Status: $($response.StatusCode))" -ForegroundColor Green
                if ($Verbose) {
                    Write-Host "   Server: $($response.Headers.Server)" -ForegroundColor Gray
                    Write-Host "   Content-Type: $($response.Headers.'Content-Type')" -ForegroundColor Gray
                }
                $successCount++
            } else {
                Write-Host "⚠️ HTTP request returned status: $($response.StatusCode)" -ForegroundColor Yellow
            }
        } catch {
            Write-Host "❌ HTTP request failed: $($_.Exception.Message)" -ForegroundColor Red
        }
        
        Start-Sleep -Milliseconds 500
    }
    
    return $successCount
}

# Function to test SQL injection detection
function Test-SQLInjection {
    param([string]$BaseUrl)
    
    $injectionPayloads = @(
        "admin' OR '1'='1",
        "' UNION SELECT * FROM users --",
        "'; DROP TABLE users; --"
    )
    
    Write-Host "🔥 Testing SQL injection detection..." -ForegroundColor Red
    
    foreach ($payload in $injectionPayloads) {
        try {
            $encodedPayload = [System.Web.HttpUtility]::UrlEncode($payload)
            $url = "$BaseUrl/login?user=admin&pass=$encodedPayload"
            
            Write-Host "🔍 Testing payload: $payload" -ForegroundColor White
            
            $response = Invoke-WebRequest -Uri $url -Method GET -TimeoutSec 10 -ErrorAction Stop
            Write-Host "✅ SQL injection attempt logged (Status: $($response.StatusCode))" -ForegroundColor Green
        } catch {
            Write-Host "⚠️ SQL injection test error: $($_.Exception.Message)" -ForegroundColor Yellow
        }
        
        Start-Sleep -Milliseconds 500
    }
}

# Function to check if services are listening
function Test-ListeningPorts {
    Write-Host "🔍 Checking if honeypot ports are listening..." -ForegroundColor White
    
    $ports = @(2222, 8080, 5000)
    $listeningPorts = @()
    
    foreach ($port in $ports) {
        $connections = Get-NetTCPConnection -LocalPort $port -State Listen -ErrorAction SilentlyContinue
        if ($connections) {
            $serviceName = switch ($port) {
                2222 { "SSH Honeypot" }
                8080 { "HTTP Honeypot" }
                5000 { "Dashboard" }
            }
            Write-Host "✅ $serviceName listening on port $port" -ForegroundColor Green
            $listeningPorts += $port
        } else {
            $serviceName = switch ($port) {
                2222 { "SSH Honeypot" }
                8080 { "HTTP Honeypot" }
                5000 { "Dashboard" }
            }
            Write-Host "❌ $serviceName not listening on port $port" -ForegroundColor Red
        }
    }
    
    return $listeningPorts
}

# Main testing logic
Write-Host "📋 Step 1: Checking listening ports..." -ForegroundColor Cyan
$listeningPorts = Test-ListeningPorts
Write-Host ""

$sshSuccess = $false
$httpSuccess = $false

if (-not $SkipSSH -and 2222 -in $listeningPorts) {
    Write-Host "📋 Step 2: Testing SSH honeypot..." -ForegroundColor Cyan
    $sshSuccess = Test-TCPConnection -Host "127.0.0.1" -Port 2222 -ServiceName "SSH"
    Write-Host ""
}

if (-not $SkipHTTP -and 8080 -in $listeningPorts) {
    Write-Host "📋 Step 3: Testing HTTP honeypot..." -ForegroundColor Cyan
    $httpRequestCount = Test-HTTPHoneypot -BaseUrl "http://127.0.0.1:8080"
    $httpSuccess = $httpRequestCount -gt 0
    Write-Host ""
    
    if ($httpSuccess) {
        Write-Host "📋 Step 4: Testing SQL injection detection..." -ForegroundColor Cyan
        Test-SQLInjection -BaseUrl "http://127.0.0.1:8080"
        Write-Host ""
    }
}

# Dashboard test
if (5000 -in $listeningPorts) {
    Write-Host "📋 Step 5: Testing dashboard accessibility..." -ForegroundColor Cyan
    try {
        $dashboardResponse = Invoke-WebRequest -Uri "http://127.0.0.1:5000" -Method GET -TimeoutSec 10
        if ($dashboardResponse.StatusCode -eq 200) {
            Write-Host "✅ Dashboard accessible at http://127.0.0.1:5000" -ForegroundColor Green
        }
    } catch {
        Write-Host "❌ Dashboard not accessible: $($_.Exception.Message)" -ForegroundColor Red
    }
    Write-Host ""
}

# Summary
Write-Host "📊 Test Summary:" -ForegroundColor Cyan
Write-Host "=" * 30 -ForegroundColor Cyan

$totalTests = 0
$passedTests = 0

if (-not $SkipSSH) {
    $totalTests++
    if ($sshSuccess) { $passedTests++ }
    $status = if ($sshSuccess) { "✅ PASS" } else { "❌ FAIL" }
    Write-Host "SSH Honeypot: $status" -ForegroundColor $(if ($sshSuccess) { "Green" } else { "Red" })
}

if (-not $SkipHTTP) {
    $totalTests++
    if ($httpSuccess) { $passedTests++ }
    $status = if ($httpSuccess) { "✅ PASS" } else { "❌ FAIL" }
    Write-Host "HTTP Honeypot: $status" -ForegroundColor $(if ($httpSuccess) { "Green" } else { "Red" })
}

Write-Host ""
if ($passedTests -eq $totalTests -and $totalTests -gt 0) {
    Write-Host "🎉 All tests passed! PHIDS honeypots are working correctly." -ForegroundColor Green
    Write-Host ""
    Write-Host "💡 Next steps:" -ForegroundColor Yellow
    Write-Host "   1. Open http://127.0.0.1:5000 in your browser" -ForegroundColor White
    Write-Host "   2. Watch the dashboard for real-time attack detection" -ForegroundColor White
    Write-Host "   3. Run more tests to generate additional data" -ForegroundColor White
} else {
    Write-Host "⚠️ Some tests failed. Check the output above for details." -ForegroundColor Yellow
    Write-Host ""
    Write-Host "🔧 Troubleshooting:" -ForegroundColor Yellow
    Write-Host "   1. Ensure PHIDS is running: python main.py --debug" -ForegroundColor White
    Write-Host "   2. Check Windows Firewall settings" -ForegroundColor White
    Write-Host "   3. Verify no other services are using ports 2222, 8080, 5000" -ForegroundColor White
}

Write-Host ""
Write-Host "📖 For more help, see the Windows troubleshooting section in README.md" -ForegroundColor Cyan
