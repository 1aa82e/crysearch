#include <Windows.h>
#include <stdio.h>

//By including comdef.h before the DepCheck SDK, we allow for smart pointers to be defined.
#include <comdef.h>
#include "../../include/DepCheckSDK.h"


void exampleFunction()
{
    IDepCheckPtr depCheck;
    if( SUCCEEDED( DepCheckCreate( DEPCHECK_SDK_VERSION, &depCheck ) ) ) {
        printf( "Total number of objects alive after create: %d\n", DepGlobalObjectCount() );
        BSTR sysInfo;
        if( depCheck->SystemInfoString( &sysInfo ) ) {
            printf( "SystemInfo: %ws\n", sysInfo );
            DepFreeString( sysInfo );
        }
    }
    //We do not need to call depCheck->Release here, when the IDepCheckPtr goes out of scope, it will auto-destruct
}


int main( int argc, char* argv[] )
{
    printf( "Running: %s\n", argv[0] );
    printf( "Total number of objects alive before: %d\n", DepGlobalObjectCount() );
    exampleFunction();
    printf( "Total number of objects alive after returning: %d\n", DepGlobalObjectCount() );
    return 0;
}
