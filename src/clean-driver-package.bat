@echo off

:: Visual studio will only clean the driver package directory when making a rebuild of the project
:: So for a regular build the directory could contain all kinds of old cruft.

if [%1]==[] goto ABORT_ARGUMENTS

:: Argument 1 is a quoted string containing an absolute path.

set OUTPUT_DIR=%1

pushd %OUTPUT_DIR%

echo Cleaning driver package of old cruft

rmdir /s /q mullvad-split-tunnel

popd

exit /b 0

:ABORT_ARGUMENTS

echo ERROR: %0 invoked without enough arguments

exit /b 1
