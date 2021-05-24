#include "classify.h"

namespace firewall
{

void
ClassificationReset
(
	FWPS_CLASSIFY_OUT0 *ClassifyOut
)
{
	//
	// According to documentation, FwpsAcquireWritableLayerDataPointer0() will update the
	// `actionType` and `rights` fields with poorly chosen values:
	//
	// ```
	// classifyOut->actionType = FWP_ACTION_BLOCK
	// classifyOut->rights &= ~FWPS_RIGHT_ACTION_WRITE
	// ```
	//
	// However, in practice it seems to not make any changes to those fields.
	// But if it did we'd want to ensure the fields have sane values.
	//

	ClassifyOut->actionType = FWP_ACTION_CONTINUE;
	ClassifyOut->rights |= FWPS_RIGHT_ACTION_WRITE;
}

void
ClassificationApplyHardPermit
(
	FWPS_CLASSIFY_OUT0 *ClassifyOut
)
{
	ClassifyOut->actionType = FWP_ACTION_PERMIT;
	ClassifyOut->rights &= ~FWPS_RIGHT_ACTION_WRITE;
}

void
ClassificationApplyHardBlock
(
	FWPS_CLASSIFY_OUT0 *ClassifyOut
)
{
	ClassifyOut->actionType = FWP_ACTION_BLOCK;
	ClassifyOut->rights &= ~FWPS_RIGHT_ACTION_WRITE;
}

} // namespace firewall
