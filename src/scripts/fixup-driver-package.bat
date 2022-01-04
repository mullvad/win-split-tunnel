@echo off

if [%1]==[] goto ABORT_ARGUMENTS

:: Argument 1 is a quoted string containing an absolute path.

set OUTPUT_DIR=%1

pushd %OUTPUT_DIR%

echo Copying debug info into driver package

copy /y /b mullvad-split-tunnel.pdb mullvad-split-tunnel\

:: Some silly component somewhere will insist on always including the KMDF Co-installer.
:: There appears to be no way of suppressing this using configuration changes.
:: So we'll just remove the file after-the-fact.

echo Removing WDF Co-installer from driver package

del "mullvad-split-tunnel\wdfcoinstaller*.dll"

popd

exit /b 0

:ABORT_ARGUMENTS

echo ERROR: %0 invoked without enough arguments

exit /b 1
