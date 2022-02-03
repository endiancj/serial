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
#include <devguid.h>
#include <devpkey.h>
#include <cstring>

using serial::PortInfo;
using std::vector;
using std::string;

static const DWORD port_name_max_length = 256;
static const DWORD hardware_id_max_length = 256;
static const DWORD bus_reported_device_desc_max_length = 256;

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

	SP_DEVINFO_DATA device_info_data;
	unsigned int device_info_set_index = 0;

	HDEVINFO device_info_set = SetupDiGetClassDevs(
		(const GUID *) &GUID_DEVCLASS_PORTS,
		NULL,
		NULL,
		DIGCF_PRESENT);

	device_info_data.cbSize = sizeof(SP_DEVINFO_DATA);

	while(SetupDiEnumDeviceInfo(device_info_set, device_info_set_index, &device_info_data))
	{
		device_info_set_index++;

        TCHAR device_instance_id[MAX_DEVICE_ID_LEN]; // Corresponds to "Device instance path" in device manager

        // Get VID, PID and serialnumber
        CM_Get_Device_ID(device_info_data.DevInst, device_instance_id, MAX_DEVICE_ID_LEN, 0);

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

        // Get bus reported device description (aka iProduct)

        wchar_t bus_reported_device_desc[bus_reported_device_desc_max_length] = {0};
        DWORD bus_reported_device_desc_actual_len = 0;
        DEVPROPTYPE property_type;

		BOOL success = SetupDiGetDevicePropertyW(device_info_set,
                                                 &device_info_data,
                                                 &DEVPKEY_Device_BusReportedDeviceDesc,
                                                 &property_type,
                                                 (PBYTE)bus_reported_device_desc,
                                                 bus_reported_device_desc_max_length,
                                                 &bus_reported_device_desc_actual_len,
                                                 0);

        if (success && bus_reported_device_desc_actual_len > 0) {
            bus_reported_device_desc[bus_reported_device_desc_actual_len-1] = '\0';
        }
        else {
            bus_reported_device_desc[0] = '\0';
        }

        // convert wchar_t to std::string
        std::wstring ws(bus_reported_device_desc);
        std::string busReportedDeviceDesc( ws.begin(), ws.end() );

		#ifdef UNICODE
			std::string portName = utf8_encode(port_name);
            std::string deviceInstanceId = utf8_encode(device_instance_id);
		#else
			std::string portName = port_name;
            std::string deviceInstanceId = device_instance_id;
		#endif

        // find serialnumber (comes after pid substring) and prefix with "SNR="
        // to make parsing of serialnumber similar to how it's done on linux/macos
        std::string pid = "PID_0678\\";
        std::size_t index = deviceInstanceId.find(pid);
        if (index != std::string::npos) {
            deviceInstanceId.insert(index + pid.length(),"SNR=");
        }

		PortInfo port_entry;
		port_entry.port = portName;
		port_entry.description = busReportedDeviceDesc;
		port_entry.hardware_id = deviceInstanceId;

		devices_found.push_back(port_entry);
	}

	SetupDiDestroyDeviceInfoList(device_info_set);

	return devices_found;
}

#endif // #if defined(_WIN32)
