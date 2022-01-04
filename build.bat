@echo off

if [%VisualStudioVersion%]==[] (
  echo Please launch this build script from a Visual Studio command prompt
  exit /b 1
)

if [%1]==[] goto USAGE

set CERT_THUMBPRINT=%1
set TIMESTAMP_SERVER=http://timestamp.digicert.com

set ROOT=%~dp0

:: Force complete rebuild

rmdir /s /q %ROOT%bin

:: Build driver but do not sign it
:: It's not possible to control all arguments to signtool through msbuild

msbuild.exe %ROOT%src\mullvad-split-tunnel.vcxproj /p:Configuration=Release /p:Platform=x64 /p:SignMode=Off

IF %ERRORLEVEL% NEQ 0 goto ERROR

:: Sign driver

signtool sign /tr %TIMESTAMP_SERVER% /td sha256 /fd sha256 /sha1 "%CERT_THUMBPRINT%" /v %ROOT%bin\x64-Release\mullvad-split-tunnel\mullvad-split-tunnel.sys

IF %ERRORLEVEL% NEQ 0 goto ERROR

:: Re-generate catalog file now that driver binary has changed

del %ROOT%bin\x64-Release\mullvad-split-tunnel\mullvad-split-tunnel.cat
"%WindowsSdkVerBinPath%x86\inf2cat.exe" /driver:%ROOT%bin\x64-Release\mullvad-split-tunnel /os:"10_x64" /verbose

IF %ERRORLEVEL% NEQ 0 goto ERROR

:: Sign catalog

signtool sign /tr %TIMESTAMP_SERVER% /td sha256 /fd sha256 /sha1 "%CERT_THUMBPRINT%" /v %ROOT%bin\x64-Release\mullvad-split-tunnel\mullvad-split-tunnel.cat

IF %ERRORLEVEL% NEQ 0 goto ERROR

:: Copy artifacts

rmdir /s /q %ROOT%bin\dist

mkdir %ROOT%bin\dist\legacy
copy /b %ROOT%bin\x64-Release\mullvad-split-tunnel\* %ROOT%bin\dist\legacy\

mkdir %ROOT%bin\dist\meta
move %ROOT%bin\dist\legacy\mullvad-split-tunnel.pdb %ROOT%bin\dist\meta\

::
:: Build a CAB file for submission to the MS Hardware Dev Center
:: The co-installer has to be included (?) because it's referenced in the inf file
::

mkdir %ROOT%bin\dist\win10

>"%ROOT%bin\dist\win10\mullvad-split-tunnel-amd64.ddf" (
    echo .OPTION EXPLICIT     ; Generate errors
    echo .Set CabinetFileCountThreshold=0
    echo .Set FolderFileCountThreshold=0
    echo .Set FolderSizeThreshold=0
    echo .Set MaxCabinetSize=0
    echo .Set MaxDiskFileCount=0
    echo .Set MaxDiskSize=0
    echo .Set CompressionType=MSZIP
    echo .Set Cabinet=on
    echo .Set Compress=on
    echo .Set CabinetNameTemplate=mullvad-split-tunnel-amd64.cab
    echo .Set DestinationDir=Package
    echo .Set DiskDirectoryTemplate=%ROOT%bin\dist\win10
    echo %ROOT%bin\dist\legacy\mullvad-split-tunnel.cat
    echo %ROOT%bin\dist\legacy\mullvad-split-tunnel.inf
    echo %ROOT%bin\dist\legacy\mullvad-split-tunnel.sys
    echo %ROOT%bin\dist\legacy\WdfCoinstaller01011.dll
)

::
:: makecab produces several garbage files
:: force current working directory to prevent spreading them out
::

pushd %ROOT%bin\dist\win10

makecab /f "%ROOT%bin\dist\win10\mullvad-split-tunnel-amd64.ddf"

popd

IF %ERRORLEVEL% NEQ 0 goto ERROR

signtool sign /tr %TIMESTAMP_SERVER% /td sha256 /fd sha256 /sha1 "%CERT_THUMBPRINT%" /v %ROOT%bin\dist\win10\mullvad-split-tunnel-amd64.cab

IF %ERRORLEVEL% NEQ 0 goto ERROR

echo;
echo BUILD COMPLETED SUCCESSFULLY
echo;

exit /b 0

:USAGE

echo Usage: %0 ^<cert_sha1_hash^>
exit /b 1

:ERROR

echo;
echo !!! BUILD FAILED !!!
echo;

exit /b 1
