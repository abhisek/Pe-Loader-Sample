#include "PeLdr.h"
#include "Debug.h"

static
INT ShowUsage()
{
	printf("-- PE Loader Sample --\n\n");
	printf("PeLdr [PE-File]\n");
	printf("\n");

	return 0;
}

int wmain(int argc, wchar_t *argv[])
{
	PE_LDR_PARAM peLdr;

	if(argc < 2)
		return ShowUsage();

	PeLdrInit(&peLdr);
	PeLdrSetExecutablePath(&peLdr, argv[1]);
	PeLdrStart(&peLdr);

	return 0;
}