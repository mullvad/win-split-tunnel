#pragma once

namespace parentchain
{

enum class RESULT
{
	NO_SPLIT_ANCESTOR,
	SPLIT_ANCESTOR,
	CYCLE,
};

//
// Parent PIDs can refer to unrelated processes after PID recycling.
// Never assume the user-provided process tree is acyclic.
//
template<typename TContext, typename TEntry, typename TGetParent, typename TIsSplit>
static
RESULT
Evaluate
(
	TContext *Context,
	TEntry *Entry,
	TGetParent GetParent,
	TIsSplit IsSplit
)
{
	auto current = Entry;
	auto fast = Entry;
	auto splitAncestor = false;
	auto detectCycles = true;

	for (;;)
	{
		current = GetParent(Context, current);

		if (current == nullptr)
		{
			return splitAncestor ? RESULT::SPLIT_ANCESTOR : RESULT::NO_SPLIT_ANCESTOR;
		}

		splitAncestor |= IsSplit(current);

		if (!detectCycles)
		{
			continue;
		}

		fast = GetParent(Context, fast);

		if (fast != nullptr)
		{
			fast = GetParent(Context, fast);
		}

		if (fast == nullptr)
		{
			detectCycles = false;
		}
		else if (current == fast)
		{
			return RESULT::CYCLE;
		}
	}
}

} // namespace parentchain
