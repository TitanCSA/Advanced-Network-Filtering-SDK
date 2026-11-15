#include "../SDK/AdvancedNetwork.h"
#include <windows.h>
#include <setupapi.h>
#include <vector>
#include <array>
#include <cstring>
#include <iostream>
#include <random>
#include <stdexcept>
#define CHECK(x) do{if(!(x))throw std::runtime_error(#x);}while(false)
int wmain(int argc,wchar_t** argv){try{
 CHECK(argc==2&&std::wstring(argv[1])==L"--lab-fuzz");wchar_t model[128]{};DWORD size=sizeof(model);CHECK(RegGetValueW(HKEY_LOCAL_MACHINE,L"HARDWARE\\DESCRIPTION\\System\\BIOS",L"SystemProductName",RRF_RT_REG_SZ,nullptr,model,&size)==ERROR_SUCCESS&&std::wstring(model)==L"Virtual Machine");
 const GUID guid={0x48c8ad62,0x2408,0x4882,{0xaf,0x6b,0x53,0xd5,0x21,0x39,0xa6,0x14}};
 struct Set{HDEVINFO h=INVALID_HANDLE_VALUE;~Set(){if(h!=INVALID_HANDLE_VALUE)SetupDiDestroyDeviceInfoList(h);}} set;set.h=SetupDiGetClassDevsW(&guid,nullptr,nullptr,DIGCF_DEVICEINTERFACE|DIGCF_PRESENT);CHECK(set.h!=INVALID_HANDLE_VALUE);
 SP_DEVICE_INTERFACE_DATA iface{};iface.cbSize=sizeof(iface);CHECK(SetupDiEnumDeviceInterfaces(set.h,nullptr,&guid,0,&iface));DWORD required=0;SetupDiGetDeviceInterfaceDetailW(set.h,&iface,nullptr,0,&required,nullptr);CHECK(required>=sizeof(SP_DEVICE_INTERFACE_DETAIL_DATA_W)&&required<=65536);
 std::vector<unsigned char> storage(required);auto detail=reinterpret_cast<SP_DEVICE_INTERFACE_DETAIL_DATA_W*>(storage.data());detail->cbSize=sizeof(*detail);CHECK(SetupDiGetDeviceInterfaceDetailW(set.h,&iface,detail,required,nullptr,nullptr));
 struct Device{HANDLE h=INVALID_HANDLE_VALUE;~Device(){if(h!=INVALID_HANDLE_VALUE)CloseHandle(h);}} device;device.h=CreateFileW(detail->DevicePath,GENERIC_READ|GENERIC_WRITE,0,nullptr,OPEN_EXISTING,0,nullptr);CHECK(device.h!=INVALID_HANDLE_VALUE);
 std::array<unsigned char,sizeof(ANF_REQUEST)+16> input{};std::array<unsigned char,sizeof(ANF_BATCH)+16> output{};std::minstd_rand random(615902);
 for(unsigned n=0;n<20000;++n){for(auto& byte:input)byte=static_cast<unsigned char>(random());ANF_REQUEST config{};config.Magic=ANF_MAGIC;config.Version=ANF_VERSION;config.Size=sizeof(config);
  if(n%3)std::memcpy(input.data()+1,&config,sizeof(config));const auto length=n%3?sizeof(config):random()%input.size();const DWORD code=n%5?ANF_IOCTL_STATUS:ANF_IOCTL_START;
  DWORD returned=0;DeviceIoControl(device.h,code,input.data()+1,static_cast<DWORD>(length),output.data()+1,static_cast<DWORD>(random()%output.size()),&returned,nullptr);
 }
 ANF_REQUEST stop{};stop.Magic=ANF_MAGIC;stop.Version=ANF_VERSION;stop.Size=sizeof(stop);DWORD returned=0;CHECK(DeviceIoControl(device.h,ANF_IOCTL_STOP,&stop,sizeof(stop),nullptr,0,&returned,nullptr));
 ANF_STATUS status{};CHECK(DeviceIoControl(device.h,ANF_IOCTL_STATUS,&stop,sizeof(stop),&status,sizeof(status),&returned,nullptr)&&returned==sizeof(status)&&!status.Active);
 std::cout<<"20,000 real buffered IOCTL boundary/malformed requests and clean owner close passed\n";return 0;
 }catch(const std::exception& e){std::cerr<<e.what()<<'\n';return 1;}}
