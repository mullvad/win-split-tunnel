#include "../src/parentchain.h"

#include <cstdlib>
#include <iostream>

namespace
{

struct ENTRY
{
	ENTRY *Parent;
	bool Split;
};

ENTRY *GetParent(void *, ENTRY *Entry)
{
	return Entry->Parent;
}

bool IsSplit(const ENTRY *Entry)
{
	return Entry->Split;
}

bool ApplyInheritance(ENTRY *Entry)
{
	if (Entry->Split)
	{
		return true;
	}

	const auto result = parentchain::Evaluate((void *)nullptr, Entry, GetParent, IsSplit);

	if (result == parentchain::RESULT::SPLIT_ANCESTOR)
	{
		Entry->Split = true;
	}

	return result != parentchain::RESULT::CYCLE;
}

void Expect(bool Condition, const char *Description)
{
	if (!Condition)
	{
		std::cerr << "FAILED: " << Description << '\n';
		std::exit(EXIT_FAILURE);
	}
}

void TestAcyclicInheritance()
{
	ENTRY root = { nullptr, true };
	ENTRY parent = { &root, false };
	ENTRY child = { &parent, false };

	Expect(ApplyInheritance(&child), "acyclic chain is valid");
	Expect(child.Split, "acyclic child inherits split state");
}

void TestSelfCycle()
{
	ENTRY child = { nullptr, false };
	child.Parent = &child;

	Expect(!ApplyInheritance(&child), "self-cycle is rejected");
	Expect(!child.Split, "self-cycle fallback remains unsplit");
}

void TestTwoNodeCycle()
{
	ENTRY first = { nullptr, false };
	ENTRY second = { &first, false };
	first.Parent = &second;

	Expect(!ApplyInheritance(&first), "two-node cycle is rejected");
	Expect(!first.Split, "two-node cycle fallback remains unsplit");
}

void TestThreeNodeCycle()
{
	ENTRY first = { nullptr, false };
	ENTRY second = { nullptr, false };
	ENTRY third = { &first, false };
	first.Parent = &second;
	second.Parent = &third;

	Expect(!ApplyInheritance(&first), "three-node cycle is rejected");
	Expect(!first.Split, "three-node cycle fallback remains unsplit");
}

void TestConfiguredChildInCycle()
{
	ENTRY child = { nullptr, true };
	child.Parent = &child;

	Expect(ApplyInheritance(&child), "configured child does not depend on ancestry");
	Expect(child.Split, "configured child remains split");
}

void TestSplitAncestorInCycleIsPrivacySafe()
{
	ENTRY child = { nullptr, false };
	ENTRY splitParent = { nullptr, true };
	ENTRY other = { &splitParent, false };
	child.Parent = &splitParent;
	splitParent.Parent = &other;

	Expect(!ApplyInheritance(&child), "cyclic split ancestry is rejected");
	Expect(!child.Split, "cyclic split ancestry cannot create a VPN bypass");
}

} // namespace

int main()
{
	TestAcyclicInheritance();
	TestSelfCycle();
	TestTwoNodeCycle();
	TestThreeNodeCycle();
	TestConfiguredChildInCycle();
	TestSplitAncestorInCycleIsPrivacySafe();

	std::cout << "All parent-chain tests passed\n";
	return EXIT_SUCCESS;
}
