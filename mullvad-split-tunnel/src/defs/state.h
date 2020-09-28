#pragma once

//
// All possible states in the driver.
//

enum ST_DRIVER_STATE
{
	// Default state after being loaded.
	ST_DRIVER_STATE_NONE = 0,

	// DriverEntry has completed successfully.
	// Basically only driver and device objects are created at this point.
	ST_DRIVER_STATE_STARTED = 1,

	// All subsystems are initialized.
	ST_DRIVER_STATE_INITIALIZED = 2,

	// User mode has registered all processes in the system.
	ST_DRIVER_STATE_READY = 3,

	// IP addresses are registered.
	// A valid configuration is registered.
	ST_DRIVER_STATE_ENGAGED = 4,

	// Driver is unloading.
	ST_DRIVER_STATE_TERMINATING = 5,
};
