#include <winsock2.h>
#include <ws2tcpip.h>
#include "../SDK/AdvancedNetwork.h"
#include <windows.h>
#include <iostream>
#include <stdexcept>
#define CHECK(x) do{if(!(x))throw std::runtime_error(#x);}while(false)
struct Socket {SOCKET s=socket(AF_INET,SOCK_STREAM,IPPROTO_TCP);~Socket(){if(s!=INVALID_SOCKET)closesocket(s);}};
int Connect(sockaddr_in address){Socket client;CHECK(client.s!=INVALID_SOCKET);const auto result=connect(client.s,reinterpret_cast<const sockaddr*>(&address),sizeof(address));return result==0?0:WSAGetLastError();}
int wmain(int argc,wchar_t** argv){try{
 CHECK(argc==2&&std::wstring(argv[1])==L"--live");wchar_t model[128]{};DWORD length=sizeof(model);CHECK(RegGetValueW(HKEY_LOCAL_MACHINE,L"HARDWARE\\DESCRIPTION\\System\\BIOS",L"SystemProductName",RRF_RT_REG_SZ,nullptr,model,&length)==ERROR_SUCCESS&&std::wstring(model)==L"Virtual Machine");
 WSADATA data{};CHECK(WSAStartup(MAKEWORD(2,2),&data)==0);struct Winsock{~Winsock(){WSACleanup();}} winsock;
 Socket listener;CHECK(listener.s!=INVALID_SOCKET);sockaddr_in address{};address.sin_family=AF_INET;address.sin_addr.s_addr=htonl(INADDR_LOOPBACK);
 CHECK(bind(listener.s,reinterpret_cast<sockaddr*>(&address),sizeof(address))==0);CHECK(listen(listener.s,16)==0);int bytes=sizeof(address);CHECK(getsockname(listener.s,reinterpret_cast<sockaddr*>(&address),&bytes)==0);
 AdvancedNetwork::Session session;session.Start(true);auto initial=session.Status();CHECK(initial.Active&&initial.DemoStarted);CHECK(Connect(address)==0);
 wchar_t executable[32768]{};auto size=GetModuleFileNameW(nullptr,executable,32768);CHECK(size&&size<32768);
 session.SetRules({AdvancedNetwork::RuleForApplication(1,executable,ANF_ACTION_BLOCK,6,ntohs(address.sin_port),L"127.0.0.1/32")});
 CHECK(Connect(address)==WSAEACCES);auto status=session.Status();CHECK(status.Blocked);
 bool observed=false;for(unsigned poll=0;poll<20&&!observed;++poll){for(const auto& e:session.Read())if(e.RuleId==1&&e.Decision==ANF_ACTION_BLOCK&&e.ProcessId==GetCurrentProcessId())observed=true;if(!observed)Sleep(10);}CHECK(observed);
 session.SetRules({});CHECK(Connect(address)==0);session.Stop();session.Start();CHECK(session.Status().DemoRemaining100ns<=initial.DemoRemaining100ns);session.Stop();
 std::cout<<"Live WFP loopback allow/app-ID block/policy-clear/events and persistent demo passed\n";return 0;
 }catch(const std::exception& e){std::cerr<<e.what()<<'\n';return 1;}}
