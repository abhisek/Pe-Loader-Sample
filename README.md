Simple runtime C++ crypter.

---------------------------------------------------------------------------------------------

The XOR-Cipher-Executable program accepts a windows executable as argument. It will run a simple XOR cipher to encrypt the binary and then output it as 'crypt.exe'.

The Pe-Loader-Sample originally comes from https://github.com/abhisek/Pe-Loader-Sample. It has been modified from the original to take a binary file from it's resources and reverse the XOR cipher from the previous program. The program then takes this unencrypted executable image in memory and proceeds with the original code to map the PE file into memory, perform relocation fix ups, resolve imports, etc, as in abhisek's original code.

---------------------------------------------------------------------------------------------

Instructions:

XOR-Cipher-Executable

Run the executable you would like to crypt through the encrypt.exe program (note that this project is based on abhisek's PE-Loader, not all executables guaranteed to work work). The resulting output will be an encrypted version of your executable called "crypt.exe".

Pe-Loader-Sample

Now load the Pe-Loader project in Visual Studio, where the encrypted program must be added as a resource. Go to View->Solution Explorer, which shows the project solution files in the tab on the left. Now right click on the project folder, and go to Add->Resource->Import(Find File) and set type as 'RCDATA', and then compile the project. When executed, the program should take the resource, decrypt it and then execute directly from process memory.

Changes to Pe-Loader-Sample:

Removed arguments from main(), removed the PeLdrSetExecutablePath and PeLdrSetExecutableBuffer functions, and heavily modified the PeLdrLoadImage to load executable into buffer from resource and not disk, and then XOR decrypt the executable before sending the unencrypted binary image to be loaded into and executed from memory (never touches disk) by the rest of the program, which is unaltered, same as the original. For original Pe-Loader code, see github link above.
