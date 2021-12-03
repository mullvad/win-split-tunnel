#pragma once

#include "wfp.h"

namespace firewall
{

void
ClassificationReset
(
	FWPS_CLASSIFY_OUT0 *ClassifyOut
);

void
ClassificationApplyHardPermit
(
	FWPS_CLASSIFY_OUT0 *ClassifyOut
);

void
ClassificationApplySoftPermit
(
	FWPS_CLASSIFY_OUT0 *ClassifyOut
);

void
ClassificationApplyHardBlock
(
	FWPS_CLASSIFY_OUT0 *ClassifyOut
);

} // namespace firewall
