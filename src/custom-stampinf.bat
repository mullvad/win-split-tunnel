@echo off

:: Visual Studio invokes the pre-build event only after it executes stampinf.
:: Therefore, any scheme to attempt to set STAMPINF_VERSION (using e.g. setx) during a pre-build event, is doomed to fail.
:: You also cannot disable stampinf being called by Visual Studio.
:: So what we'll do is run stampinf again, with the correct version data.
:: 

if [%1]==[] goto ABORT_ARGUMENTS
if [%2]==[] goto ABORT_ARGUMENTS
if [%3]==[] goto ABORT_ARGUMENTS
if [%4]==[] goto ABORT_ARGUMENTS
if [%5]==[] goto ABORT_ARGUMENTS

:: Arguments 1, 4, 5 are quoted strings containing absolute paths.
:: This avoids any issues with spaces in paths, quotes, concatenation.

set INF_BINARY=%1
set INF_ARCH=%2
set DRIVER_KMDF_VERSION=%3
set INTERMEDIATE_DIR_TARGET=%4
set OUTPUT_DIR_TARGET=%5

setlocal enabledelayedexpansion

:: Import version defines into environment

for /f "tokens=1-3 delims= " %%i in (%~dp0\version.h) do (
	if /i "%%i"=="#define" (
		set %%j=%%k
	)
)

set DRIVER_VERSION=%DRIVER_VERSION_MAJOR%.%DRIVER_VERSION_MINOR%.%DRIVER_VERSION_PATCH%.%DRIVER_VERSION_BUILD%

:: Broken actions such as the DriverPackageTarget references the intermediate INF
:: So we have to re-stamp the intermediate file and copy it to the output directory, so they're both up-to-date

echo Stamping INF again with correct version data

%INF_BINARY% -d "*" -a "%INF_ARCH%" -v "%DRIVER_VERSION%" -k "%DRIVER_KMDF_VERSION%" -f %INTERMEDIATE_DIR_TARGET%

if %ERRORLEVEL% neq 0 goto FAILED_STAMP

copy /y /b %INTERMEDIATE_DIR_TARGET% %OUTPUT_DIR_TARGET%

exit /b 0

:ABORT_ARGUMENTS

echo ERROR: %0 invoked without enough arguments

exit /b 1

:FAILED_STAMP

echo ERROR: %0 has failed

exit /b 1
