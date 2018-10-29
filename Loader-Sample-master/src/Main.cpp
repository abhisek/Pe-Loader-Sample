#include "PeLdr.h"
#include "Debug.h"

int wmain()
{
	PE_LDR_PARAM peLdr;

	PeLdrInit(&peLdr);
	PeLdrStart(&peLdr);

	return 0;
}
