Copyright (c) 2019, Diamond Key Security�
All rights reserved.

# diamondhsm-win-cng

------------------------------------------------
Prerequisites
------------------------------------------------
Download and Install the Cryptographic Provider Development Kit
https://www.microsoft.com/en-us/download/details.aspx?id=30688

The Project Include path will need to be updated to the path with the SDK
The default path is "C:\Program Files (x86)\Windows Kits\8.0\Cryptographic Provider Development Kit\Include"

------------------------------------------------
LibreSSL
------------------------------------------------
This solution uses prebuilt LibreSSL version 3.0.0 binaries. The binary were
created from the 3.0.0 release and can be found at https://ftp.openbsd.org/pub/OpenBSD/LibreSSL/
The binraries were built in Visual Studio 2017 using CMake.

------------------------------------------------
PKCS 11
------------------------------------------------
The generated DLL exports a working PKCS #11 interface that has been
tested with OpenSC. The Diamond-HSM does not automatically set
the CKA_CLASS attribute. The Linux and Windows PKCS #11 projects
need to be updated to add this attribute.

------------------------------------------------
Binaries
------------------------------------------------
Prebuilt binaries and installation instructions can be found in the "Binaries and Installation" folder.