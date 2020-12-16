<# 
Author: Securethelogs.com

This script is to help identify any potential malicious files for Solarwinds supply chain attack #SUNBURST
FireEye report: https://www.fireeye.com/blog/threat-research/2020/12/evasive-attacker-leverages-solarwinds-supply-chain-compromises-with-sunburst-backdoor.html

#>

$sun = @("

  ____              _                    _   
 / ___| _   _ _ __ | |__  _   _ _ __ ___| |_ 
 \___ \| | | | '_ \| '_ \| | | | '__/ __| __|
  ___) | |_| | | | | |_) | |_| | |  \__ \ |_ 
 |____/ \__,_|_| |_|_.__/ \__,_|_|  |___/\__|

 @Securethelogs

")

$sun

$badDLLhashes = @(
"2c4a910a1299cdae2a4e55988a2f102e,846e27a652a5e1bfbd0ddd38a16dc865",
"32519b85c0b422e4656de6e6c41878e95fd95026267daab4215ee59c107d6c77",
"dab758bf98d9b36fa057a66cd0284737abf89857b73ca89280267ee7caf62f3b",
"eb6fab5a2964c5817fb239a7a5079cabca0a00464fb3e07155f28b0a57a2c0ed",
"c09040d35630d75dfef0f804f320f8b3d16a481071076918e9b236a321c1ea77",
"ac1b2b89e60707a20e9eb1ca480bc3410ead40643b386d624c5d21b47c02917c",
"019085a76ba7126fff22770d71bd901c325fc68ac55aa743327984e89f4b0134",
"ce77d116a074dab7a22a0fd4f2c1ab475f16eec42e1ded3c0b0aa8211fe858d6",
"a25cadd48d70f6ea0c4a241d99c5241269e6faccb4054e62d16784640f8e53bc"
)

Write-Host "Running Script ..."
Write-Host "Finding SolarWinds.Orion.Core.BusinessLayer.dll files ..."


$businessdll = @() 
$businessdll += (Get-ChildItem "C:\Program Files (x86)\SolarWinds\" -Recurse -Include "*SolarWinds.Orion.Core.BusinessLayer.dll*" -ErrorAction SilentlyContinue).FullName
$businessdll += (Get-ChildItem "C:\Windows\System32\config\systemprofile\AppData\Local\assembly\" -Recurse -Include "*SolarWinds.Orion.Core.BusinessLayer.dll*" -ErrorAction SilentlyContinue).FullName

$bhc = 0

Write-Host "Files Found: " -NoNewline 
Write-Host $businessdll.Count

Write-Output ""

Write-Host "Locations: "
$businessdll

Write-Output ""

Write-Host "[*] Solarwinds is a bit senstive and may not allow access to the files ..."
Write-Host "[*] We can try, else we can move to a temp folder for scanning? "
Write-Host "[*] Please make sure the account used for this script has access"
Write-Output ""

$try = Read-Host -Prompt "What would you like to try as is? (Y/N)"

if ($try -ne "y"){

Write-Output ""

$folder = Read-Host -Prompt "Please enter the folder location of the DLLs: "
    
    if (Test-Path $folder){
    
    $businessdll = @(Get-ChildItem $folder -Recurse -Include "*SolarWinds.Orion.Core.BusinessLayer.dll*" -ErrorAction SilentlyContinue).FullName
    
    } else {
    
    Write-Host "[*] Error: Folder may not be correct ... trying as is ..." -ForegroundColor Red
    
    }

}


foreach ($b in $businessdll){

$hash = (Get-FileHash $b -Algorithm SHA256).Hash

    
    if ($badDLLhashes.Contains($hash)){
    
        $bhc ++
    
        Write-Host "[*] Potenital threat found: " -NoNewline -ForegroundColor Red
        Write-Host $b -NoNewline
        Write-Host " matches the bad hash: " -NoNewline
        Write-Host $bh 
    
    
    } else {
    
    
    }

}

Write-Output ""

if ($bhc -eq 0){

Write-Host "No bad hashes found ..." -ForegroundColor Green

}

Write-Output ""

Write-Host "Looking for addtional files (IOC) ... "
 
$msp = (Get-ChildItem C:\ -Recurse -Include "*CORE-2019.4.5220.20574-SolarWinds-Core-v2019.4.5220-Hotfix5.msp*"  -ErrorAction SilentlyContinue).FullName
$appweb = (Get-ChildItem C:\ -Recurse -Include "*appweblogoimagehandler.ashx.b6031896.dll*" -ErrorAction SilentlyContinue).FullName
$netdl = (Get-ChildItem "C:\Windows\syswow64\netsetupsvc.dll" -ErrorAction SilentlyContinue).FullName

if ($msp -eq $null){

Write-Host "CORE-2019.4.5220.20574-SolarWinds-Core-v2019.4.5220-Hotfix5.msp" was not found -ForegroundColor Green

} else {
    
    Write-Host "[*] CORE-2019.4.5220.20574-SolarWinds-Core-v2019.4.5220-Hotfix5.msp" was found -ForegroundColor Red -NoNewline 
    Write-Host " Location: " -NoNewline
    Write-Host $msp

    }

Write-Output ""

if ($appweb -eq $null){

Write-Host "appweblogoimagehandler.ashx.b6031896.dll" was not found -ForegroundColor Green

} else {
    
    Write-Host "[*] appweblogoimagehandler.ashx.b6031896.dll" was found -ForegroundColor Red -NoNewline 
    Write-Host " Location: " -NoNewline
    Write-Host $appweb

    }

Write-Output ""

if ($netdl -eq $null){

Write-Host "netsetupsvc.dll" was not found -ForegroundColor Green

} else {
    
    Write-Host "[*] netsetupsvc.dll" was found -ForegroundColor Red -NoNewline 
    Write-Host " Location: " -NoNewline
    Write-Host $netdl

    }



Write-Output ""

Write-Output "Just to be sure, I would advise running files against the rulesets here: https://github.com/fireeye/sunburst_countermeasures"