#include "../SDK/AdvancedNetwork.h"
#include <iostream>
#include "../SDK/RuleValidation.h"
#include <stdexcept>
static void Check(bool result){if(!result)throw std::runtime_error("Offline rule/protocol regression");}
int main(){try{
    auto r=AdvancedNetwork::Rule(1,ANF_ACTION_BLOCK,6,443,L"192.168.1.99/24",42);
    Check(AdvancedNetwork::Validate(r)&&r.RemoteAddress[3]==0&&r.RemotePrefix==24);
    for(unsigned prefix=0;prefix<=128;++prefix){auto v6=AdvancedNetwork::Rule(2,0,17,53,L"2001:db8::abcd/"+std::to_wstring(prefix));Check(AdvancedNetwork::Validate(v6));}
    for(const auto& address:{L"127.0.0.1/33",L"::1/129",L"::1/-1",L"example.com",L"::1/",L"1.2.3.4/1junk"}){
        bool refused=false;try{AdvancedNetwork::Rule(1,1,6,0,address);}catch(const std::invalid_argument&){refused=true;}Check(refused);
    }
    for(unsigned action=2;action<256;++action){auto bad=r;bad.Action=static_cast<ANF_U8>(action);Check(!AdvancedNetwork::Validate(bad));}
    auto bad=r;bad.Reserved[0]=1;Check(!AdvancedNetwork::Validate(bad));bad=r;bad.Protocol=1;Check(!AdvancedNetwork::Validate(bad));
    bad=r;bad.RemoteFirst=500;bad.RemoteLast=100;Check(!AdvancedNetwork::Validate(bad));bad=r;bad.RemoteAddress[3]=1;Check(!AdvancedNetwork::Validate(bad));
    ANF_POLICY policy{};policy.Magic=ANF_MAGIC;policy.Version=ANF_VERSION;policy.Size=sizeof(policy);policy.Count=2;policy.Rules[0]=r;policy.Rules[1]=r;Check(!AdvancedNetwork::Validate(policy));
    policy.Rules[1].Id=2;Check(AdvancedNetwork::Validate(policy));policy.Count=65;Check(!AdvancedNetwork::Validate(policy));
    ANF_BATCH batch{};batch.Magic=ANF_MAGIC;batch.Version=ANF_VERSION;batch.Size=sizeof(batch);Check(AdvancedNetwork::Validate(batch,sizeof(batch)));
    batch.Count=1;auto& e=batch.Events[0];e.Sequence=1;e.TimestampQpc=1;e.Generation=1;e.Family=4;e.Direction=2;e.Stage=1;Check(AdvancedNetwork::Validate(batch,sizeof(batch)));
    e.Decision=1;Check(!AdvancedNetwork::Validate(batch,sizeof(batch)));e.RuleId=1;Check(AdvancedNetwork::Validate(batch,sizeof(batch)));
    e.Flags=2;Check(!AdvancedNetwork::Validate(batch,sizeof(batch)));e.Flags=0;e.Application[0]=1;Check(!AdvancedNetwork::Validate(batch,sizeof(batch)));
    ANF_RULE app=AdvancedNetwork::Rule(5,ANF_ACTION_BLOCK);app.AppPathBytes=4;app.AppPath[0]='a';app.AppPath[1]='b';
    Check(AdvancedNetwork::Validate(app));
    const unsigned char exact[]={97,0,98,0,0,0},wrong[]={97,0,99,0};
    Check(AnfApplicationMatches(&app,exact,sizeof(exact))!=0);
    Check(!AnfApplicationMatches(&app,wrong,sizeof(wrong))&&!AnfApplicationMatches(&app,nullptr,0));
    auto invalidApp=app;invalidApp.AppPathBytes=3;Check(!AdvancedNetwork::Validate(invalidApp));
    invalidApp=app;invalidApp.AppPathBytes=ANF_APP_CHARS*2u;Check(!AdvancedNetwork::Validate(invalidApp));
    invalidApp=app;invalidApp.AppPath[100]=1;Check(!AdvancedNetwork::Validate(invalidApp));
    Check(!AnfApplicationMatches(&app,exact,1)&&!AnfApplicationMatches(&app,exact,ANF_APP_CHARS*2u+2u));
    std::cout << "CIDR, protocol, policy and malformed-wire checks passed. No network capture or filters created.\n";
    return 0;
}catch(const std::exception& e){std::cerr<<e.what()<<'\n';return 1;}}
