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

## [1.0.3.0] - 2021-05-25
### Changed
Use improved model to determine when to split traffic. This has the following effects:
  - TCP client sockets connecting to localhost can now be used successfully.
  - Routing now works as expected, e.g. when being connected to multiple LANs.

## [1.0.2.0] - 2021-05-04
### Changed
Use less strict security descriptor on device object. The previous SD could e.g. prevent
uninstallation of the driver, since uninstallers typically are not ran as SYSTEM.

### Fixed
Various minor code changes to improve both source code and runtime consistency.


## [1.0.1.0] - 2021-03-12
### Fixed
Force reauthorization in WFP if state has changed but WFP was not updated in the process.

## [1.0.0.0] - 2021-03-10
Initial release.
