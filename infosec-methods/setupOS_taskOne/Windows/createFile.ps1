$dirParam=$args[0]
$nameParam=$args[1]
New-Item -Path $dirParam -Name $nameParam -ItemType "file"
