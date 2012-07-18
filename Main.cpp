#include <windows.h>

#include "Debug.h"
#include "PeLdr.h"

static
INT ShowUsage(int argc, char **argv)
{
	printf("-- PE Loader Sample --\n\n");
	printf("%s [PE-File]\n", argv[0]);
	printf("\n");

	return 0;
}

int main(int argc, char **argv)
{
	if(argc < 2)
		return ShowUsage(argc, argv);

}