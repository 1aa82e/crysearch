#include <Windows.h>
#include <stdio.h>
#include "../../include/DepCheckSDK.h"


int main( int argc, char* argv[] )
{
    IDepCheck* depCheck;
    printf( "Running: %s\n", argv[0] );
    printf( "Total number of objects alive before: %d\n", DepGlobalObjectCount() );
    if( SUCCEEDED( DepCheckCreate( DEPCHECK_SDK_VERSION, &depCheck ) ) ) {
        BSTR sysInfo;
        printf( "Total number of objects alive after create: %d\n", DepGlobalObjectCount() );
        if( depCheck->lpVtbl->SystemInfoString( depCheck, &sysInfo ) ) {
            printf( "SystemInfo: %ws", sysInfo );
            DepFreeString( sysInfo );
        }
        depCheck->lpVtbl->Release( depCheck );
        printf( "Total number of objects alive after Release: %d\n", DepGlobalObjectCount() );
    }
    return 0;
}
