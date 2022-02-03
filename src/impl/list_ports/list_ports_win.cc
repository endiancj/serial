#if defined(_WIN32)

/*
 * Copyright (c) 2014 Craig Lilley <cralilley@gmail.com>
 * This software is made available under the terms of the MIT licence.
 * A copy of the licence can be obtained from:
 * http://opensource.org/licenses/MIT
 */

#include "serial/serial.h"
#include <tchar.h>
#include <windows.h>
#include <setupapi.h>
#include <initguid.h>
#include <cfgmgr32.h>   // for MAX_DEVICE_ID_LEN, CM_Get_Parent and CM_Get_Device_ID
#ifndef INITGUID
#define INITGUID
#endif
#include <devguid.h>
#include <stdio.h>
#include <cstring>

using serial::PortInfo;
using std::vector;
using std::string;

#ifdef DEFINE_DEVPROPKEY
#undef DEFINE_DEVPROPKEY
#endif
#ifdef INITGUID
#define DEFINE_DEVPROPKEY(name, l, w1, w2, b1, b2, b3, b4, b5, b6, b7, b8, pid) EXTERN_C const DEVPROPKEY DECLSPEC_SELECTANY name = { { l, w1, w2, { b1, b2,  b3,  b4,  b5,  b6,  b7,  b8 } }, pid }
#else
#define DEFINE_DEVPROPKEY(name, l, w1, w2, b1, b2, b3, b4, b5, b6, b7, b8, pid) EXTERN_C const DEVPROPKEY name
#endif // INITGUID

DEFINE_DEVPROPKEY(DEVPKEY_Device_BusReportedDeviceDesc, 0x540b947e, 0x8b40, 0x45bc, 0xa8, 0xa2, 0x6a, 0x0b, 0x89, 0x4c, 0xbd, 0xa2, 4);     // DEVPROP_TYPE_STRING

static const DWORD port_name_max_length = 256;
static const DWORD friendly_name_max_length = 256;
static const DWORD hardware_id_max_length = 256;
static const DWORD device_desc_max_length = 256;

// Convert a wide Unicode string to an UTF8 string
std::string utf8_encode(const std::wstring &wstr)
{
	int size_needed = WideCharToMultiByte(CP_UTF8, 0, &wstr[0], (int)wstr.size(), NULL, 0, NULL, NULL);
	std::string strTo( size_needed, 0 );
	WideCharToMultiByte                  (CP_UTF8, 0, &wstr[0], (int)wstr.size(), &strTo[0], size_needed, NULL, NULL);
	return strTo;
}

vector<PortInfo>
serial::list_ports()
{
	vector<PortInfo> devices_found;

	unsigned i, j;
    DWORD dwSize, dwPropertyRegDataType;
    DEVPROPTYPE ulPropertyType;
    CONFIGRET status;
    SP_DEVINFO_DATA DeviceInfoData;
    const static LPCTSTR arPrefix[3] = { TEXT("VID_"), TEXT("PID_"), TEXT("MI_") };
    TCHAR szDeviceInstanceID[MAX_DEVICE_ID_LEN];
    TCHAR szHardwareIDs[4096];
    WCHAR szBuffer[4096];
    LPTSTR pszToken, pszNextToken;
    TCHAR szVid[MAX_DEVICE_ID_LEN], szPid[MAX_DEVICE_ID_LEN], szMi[MAX_DEVICE_ID_LEN];

	HDEVINFO device_info_set = SetupDiGetClassDevs(
		(const GUID *) &GUID_DEVCLASS_PORTS,
		NULL,
		NULL,
		DIGCF_PRESENT);

	unsigned int device_info_set_index = 0;
	SP_DEVINFO_DATA device_info_data;

	device_info_data.cbSize = sizeof(SP_DEVINFO_DATA);

	while(SetupDiEnumDeviceInfo(device_info_set, device_info_set_index, &device_info_data))
	{
		device_info_set_index++;

		status = CM_Get_Device_ID(device_info_data.DevInst, szDeviceInstanceID, MAX_PATH, 0);
        if (status != CR_SUCCESS)
            continue;

		// Get port name

		HKEY hkey = SetupDiOpenDevRegKey(
			device_info_set,
			&device_info_data,
			DICS_FLAG_GLOBAL,
			0,
			DIREG_DEV,
			KEY_READ);

		TCHAR port_name[port_name_max_length];
		DWORD port_name_length = port_name_max_length;

		LONG return_code = RegQueryValueEx(
					hkey,
					_T("PortName"),
					NULL,
					NULL,
					(LPBYTE)port_name,
					&port_name_length);

		RegCloseKey(hkey);

		if(return_code != EXIT_SUCCESS)
			continue;

		if(port_name_length > 0 && port_name_length <= port_name_max_length)
			port_name[port_name_length-1] = '\0';
		else
			port_name[0] = '\0';

		// Ignore parallel ports

		if(_tcsstr(port_name, _T("LPT")) != NULL)
			continue;

		// Get port device description

		TCHAR device_desc[device_desc_max_length];
		DWORD device_desc_actual_length = 0;

		BOOL got_device_desc = SetupDiGetDeviceRegistryProperty(
					device_info_set,
					&device_info_data,
					SPDRP_PHYSICAL_DEVICE_OBJECT_NAME,
					NULL,
					(PBYTE)device_desc,
					device_desc_max_length,
					&device_desc_actual_length);

		if(got_device_desc == TRUE && device_desc_actual_length > 0)
			device_desc[device_desc_actual_length-1] = '\0';
		else
			device_desc[0] = '\0';

		// Get port friendly name

		TCHAR friendly_name[friendly_name_max_length];
		DWORD friendly_name_actual_length = 0;

		BOOL got_friendly_name = SetupDiGetDeviceRegistryProperty(
					device_info_set,
					&device_info_data,
					SPDRP_FRIENDLYNAME,
					NULL,
					(PBYTE)friendly_name,
					friendly_name_max_length,
					&friendly_name_actual_length);

		if(got_friendly_name == TRUE && friendly_name_actual_length > 0)
			friendly_name[friendly_name_actual_length-1] = '\0';
		else
			friendly_name[0] = '\0';

		// Get hardware ID

		TCHAR hardware_id[hardware_id_max_length];
		DWORD hardware_id_actual_length = 0;

		BOOL got_hardware_id = SetupDiGetDeviceRegistryProperty(
					device_info_set,
					&device_info_data,
					SPDRP_HARDWAREID,
					NULL,
					(PBYTE)hardware_id,
					hardware_id_max_length,
					&hardware_id_actual_length);

		if(got_hardware_id == TRUE && hardware_id_actual_length > 0)
			hardware_id[hardware_id_actual_length-1] = '\0';
		else
			hardware_id[0] = '\0';

		if (SetupDiGetDevicePropertyW(device_info_set, &device_info_data, &DEVPKEY_Device_BusReportedDeviceDesc,
			&ulPropertyType, (BYTE*)szBuffer, sizeof(szBuffer), &dwSize, 0)) {
			printf(TEXT("    Bus Reported Device Description: \"%ls\"\n"), szBuffer);

		}

		#ifdef UNICODE
			std::string portName = utf8_encode(port_name);
			std::string friendlyName = utf8_encode(friendly_name);
			std::string hardwareId = utf8_encode(hardware_id);
			std::string deviceDesc = utf8_encode(device_desc);
			// std::string busDesc = utf8_encode(szBuffer);
		#else
			std::string portName = port_name;
			std::string friendlyName = friendly_name;
			std::string hardwareId = hardware_id;
			std::string deviceDesc = device_desc;
			// std::string busDesc = szBuffer;
		#endif

		PortInfo port_entry;
		port_entry.port = portName;
		port_entry.description = friendlyName;
		port_entry.hardware_id = hardwareId;
		port_entry.test_desc = deviceDesc;
		memcpy(port_entry.szBuffer, szBuffer, sizeof szBuffer);

		devices_found.push_back(port_entry);
	}

	SetupDiDestroyDeviceInfoList(device_info_set);

	return devices_found;
}

#endif // #if defined(_WIN32)
