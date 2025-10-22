# Changelog
All notable changes are recorded here.

### Format

The format is based on [Keep a Changelog](http://keepachangelog.com/en/1.0.0/).

Entries should have the imperative form, just like commit messages. Start each entry with words like
add, fix, increase, force etc.. Not added, fixed, increased, forced etc.

Line wrap the file at 100 chars.                                              That is over here -> |

### Categories each change fall into

* **Added**: for new features.
* **Changed**: for changes in existing functionality.
* **Deprecated**: for soon-to-be removed features.
* **Removed**: for now removed features.
* **Fixed**: for any bug fixes.
* **Security**: in case of vulnerabilities.

## [Unreleased]
### Fixed
- Attempt to clean up callouts and other resources if the driver is unexpectedly unloaded.
  In particular, the callback registered by `PsSetCreateProcessNotifyRoutineEx()` reliably
  triggered bug checks when this occurred.

### Security
- Limit I/O buffer size in IOCTLs to protect against kernel memory exhaustion attacks.
  Fixes 2024 Mullvad app audit issue item `MLLVD-CR-24-102`.

## [1.2.4.0] - 2024-08-12
### Fixed
- Fix build scripts for ARM64.


## [1.2.3.0] - 2024-07-26
### Added
- Add support for ARM64.


## [1.2.2.0] - 2022-09-22
### Changed
- Upgrade the code and build instructions to use Visual Studio 2022 instead of 2019.

### Security
- Fix incomplete validation of input buffers that could result in out-of-bounds reads.
  Fixes 2022 Mullvad app audit issue item `MUL22-01`.


## [1.2.1.0] - 2022-04-19
### Security
- For non-excluded DNS traffic, evaluate all appropriate filters within the DNS sublayer when a
  soft permit has been applied in a higher-priority sublayer.


## [1.2.0.0] - 2022-01-10
### Changed
- Update build and release procedure to remove support for pre-Windows 10 systems.

### Fixed
- Ensure IOCTL requests are always processed on worker thread to prevent client from getting stuck
  inside DeviceIoControl API call.
- Apply a soft permit on excluded traffic, rather than a hard permit. This allows firewall filters
  added by other software (e.g. Windows Defender) to evaluate and block traffic.


## [1.1.1.0] - 2021-06-04
### Fixed
- Correct unfortunate application of NT_ASSERT, the illustrious. Critical logic that updates the
  process tree was being omitted from release builds.


## [1.1.0.0] - 2021-05-26
### Changed
- Use improved model to determine when to split traffic. This has the following effects:
  - TCP client sockets connecting to localhost can now be used successfully.
  - Routing now works as expected, e.g. when being connected to multiple LANs.


## [1.0.2.0] - 2021-05-04
### Changed
- Use less strict security descriptor on device object. The previous SD could e.g. prevent
  uninstallation of the driver, since uninstallers typically are not ran as SYSTEM.

### Fixed
- Various minor code changes to improve both source code and runtime consistency.


## [1.0.1.0] - 2021-03-12
### Fixed
- Force reauthorization in WFP if state has changed but WFP was not updated in the process.

## [1.0.0.0] - 2021-03-10
Initial release.
