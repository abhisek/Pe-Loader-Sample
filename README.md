PE Loader Sample
=================

In memory execution of PE executables:

 * Self Relocation
 * Memory Mapping
 * IAT Processing
 * Relocation
 * Control Transfer
	
This project aims to implement a complete PE Loader capable of loading all PE and PE+ executables. The current version should be considered as a PoC only as it does not handle all practical cases.

TODO:

 * Handle Import Forwarding
 * Bound Imports
 * Is it possible to relocate a PE if relocation table is not included? Hack++?
 * Most Important: Documentation of PE Loading Process
	
Thanks
-------

* Special thanks to Stephen Fewer of Harmony Security for Reflective DLL Injection paper and implementation. The IAT processing and Relocation code in this project is taken from ReflectiveDLL Loader implementation.

* sincoder for ideas on Self Relocation.