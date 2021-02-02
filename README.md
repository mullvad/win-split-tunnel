# Mullvad split tunnel driver for Windows

This is a non-PnP KMDF driver suitable for implementing split tunneling in VPN client software. The driver works on Windows 7 through 10.

Main features:

- Exclude network traffic from VPN tunnel based on process paths.
- Tracking of arriving and departing processes.
- Atomic process classifications remove any races that could enable traffic leaks.
- Propagation of exclusion flag to child processes.
- Dynamic reconfiguration.
- Blocking of pre-existing unwanted connections.
- Blocking of IPv6 in cases where it would otherwise leak inside the tunnel.

# Development environment

Visual Studio 2019, any edition.

WDK, recent version.

# Architecture

The features mentioned above are wholly implemented in the driver. However, the driver needs a user mode agent to initially and continuously provide it with configuration data.

Specifically, the agent provides a set of application paths that should be excluded from the tunnel. It also communicates the tunnel IPs (IPv4/IPv6) as well as IPs of the primary network interface.

The agent is required to monitor network interfaces and update the driver with new IPs, as they change.

The code in `./testing` gives an example of building blocks needed in the agent. This code is mostly useful for manual testing. For an implementation that is more suited for production use, refer to relevant sections of the [Mullvad VPN app](https://github.com/mullvad/mullvadvpn-app)

# License

Copyright (C) 2021  Mullvad VPN AB

This program is free software: you can redistribute it and/or modify it under the terms of the
GNU General Public License as published by the Free Software Foundation, either version 3 of
the License, or (at your option) any later version.

For the full license agreement, see the LICENSE.md file
