# Remove all test scripts and temporary files
Remove-Item -Path "E:\model\behavioral-model\*.sh" -Force -ErrorAction SilentlyContinue
Remove-Item -Path "E:\model\behavioral-model\*.ps1" -Force -ErrorAction SilentlyContinue -Exclude "cleanup.ps1"

# Remove build directories
Remove-Item -Path "E:\model\behavioral-model\build*" -Recurse -Force -ErrorAction SilentlyContinue
Remove-Item -Path "E:\model\behavioral-model\test_*" -Recurse -Force -ErrorAction SilentlyContinue

Write-Host "Cleanup completed!"
