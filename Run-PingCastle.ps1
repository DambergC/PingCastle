# Set the working directory
Set-Location -Path "C:\PingCastle"

# Define the PingCastle executable path and arguments
$pingCastlePath = "C:\PingCastle\PingCastle.exe"
$pingCastleArgs = "--healthcheck --server corp.damberg.org"

# Run PingCastle with the specified arguments
Start-Process -FilePath $pingCastlePath -ArgumentList $pingCastleArgs -NoNewWindow -Wait
