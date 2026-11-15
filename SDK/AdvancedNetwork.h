#ifndef TITAN_ADVANCED_NETWORK_H
#define TITAN_ADVANCED_NETWORK_H
/* Fixed, pointer-free protocol. Defaults use the native MSVC x64 ABI. */
#define ANF_VERSION 1u
#define ANF_DEVICE_TYPE 0x8349u
#define ANF_MAGIC 0x4E46544Eu
#define ANF_RING_CAPACITY 2048u
#define ANF_READ_CAPACITY 64u
#define ANF_PATH_CAPACITY 128u
#define ANF_RULE_CAPACITY 64u
#define ANF_APP_CHARS 256u
#define ANF_STAGE_AUTHORIZE 1u
#define ANF_FLAG_PID 1u
#define ANF_FLAG_PATH 4u
#define ANF_FLAG_PATH_TRUNCATED 8u
#define ANF_FLAG_REAUTHORIZE 16u
#define ANF_FLAG_LOCAL_ADDRESS 32u
#define ANF_FLAG_REMOTE_ADDRESS 64u
#define ANF_FLAG_PORTS 128u
#define ANF_FLAG_PROTOCOL 256u
#define ANF_OPTION_INCLUDE_PATHS 1u
#define ANF_INBOUND 1u
#define ANF_OUTBOUND 2u
#define ANF_ACTION_CONTINUE 0u
#define ANF_ACTION_BLOCK 1u
#define ANF_IOCTL(function) ((ANF_DEVICE_TYPE<<16)|(3u<<14)|((0x800u+(function))<<2))
#define ANF_IOCTL_START ANF_IOCTL(1u)
#define ANF_IOCTL_STOP ANF_IOCTL(2u)
#define ANF_IOCTL_STATUS ANF_IOCTL(3u)
#define ANF_IOCTL_READ ANF_IOCTL(4u)
#define ANF_IOCTL_POLICY ANF_IOCTL(5u)
typedef unsigned char ANF_U8;
typedef unsigned short ANF_U16;
typedef unsigned int ANF_U32;
typedef unsigned long long ANF_U64;
typedef struct ANF_REQUEST { ANF_U32 Magic,Version,Size,Options; } ANF_REQUEST;
typedef struct ANF_RULE {
    ANF_U64 ProcessId; /* 0 = any; current PID, not a permanent application ID. */
    ANF_U32 Id;       /* Nonzero and unique within a policy. First match wins. */
    ANF_U16 LocalFirst,LocalLast,RemoteFirst,RemoteLast; /* 0/0 = any. */
    ANF_U8 Family,Direction,Protocol,Action; /* 0 = any, except Action. */
    ANF_U8 RemotePrefix,Reserved[3];
    ANF_U8 RemoteAddress[16]; /* Network-order CIDR bytes. */
    ANF_U32 AppPathBytes; /* Canonical WFP app-id bytes, excluding final UTF-16 NUL. */
    ANF_U16 AppPath[ANF_APP_CHARS];
} ANF_RULE;
typedef struct ANF_POLICY { ANF_U32 Magic,Version,Size,Count; ANF_RULE Rules[ANF_RULE_CAPACITY]; } ANF_POLICY;
typedef struct ANF_EVENT {
    ANF_U64 Sequence,TimestampQpc,ProcessId,Generation;
    ANF_U32 Flags,RuleId;
    ANF_U16 LocalPort,RemotePort;
    ANF_U8 Family,Stage,Protocol,Direction;
    ANF_U8 LocalAddress[16],RemoteAddress[16];
    ANF_U16 PathLength,Decision;
    ANF_U16 Application[ANF_PATH_CAPACITY];
} ANF_EVENT;
typedef struct ANF_STATUS {
    ANF_U32 Magic,Version,Size,Active;
    ANF_U64 QpcFrequency,Produced,Dropped;
    ANF_U32 Available,Capacity,Options,RuleCount;
    ANF_U64 BytesIn,BytesOut,PacketsIn,PacketsOut,Blocked,Continued,Generation;
    ANF_U32 DemoStarted,DemoExpired;
    ANF_U64 DemoRemaining100ns;
} ANF_STATUS;
typedef struct ANF_BATCH { ANF_U32 Magic,Version,Size,Count; ANF_U64 Dropped; ANF_EVENT Events[ANF_READ_CAPACITY]; } ANF_BATCH;
#ifdef __cplusplus
#include <memory>
#include <string>
#include <vector>
namespace AdvancedNetwork {
static_assert(sizeof(ANF_RULE)==560 && sizeof(ANF_EVENT)==344 && sizeof(ANF_STATUS)==128,"Unexpected ABI packing");
bool Validate(const ANF_RULE&) noexcept;
bool Validate(const ANF_POLICY&) noexcept;
bool Validate(const ANF_STATUS&) noexcept;
bool Validate(const ANF_BATCH&,std::size_t bytes) noexcept;
ANF_RULE Rule(unsigned id,unsigned action,unsigned protocol=0,unsigned remotePort=0,
             const std::wstring& remoteCidr=L"",ANF_U64 pid=0,unsigned direction=ANF_OUTBOUND);
ANF_RULE RuleForApplication(unsigned id,const std::wstring& executable,unsigned action,
    unsigned protocol=0,unsigned remotePort=0,const std::wstring& remoteCidr=L"",unsigned direction=ANF_OUTBOUND);
std::wstring Address(const ANF_EVENT&,bool remote=true);
class Session {
    struct State;
    std::unique_ptr<State> state_;
public:
    Session();
    ~Session();
    Session(const Session&)=delete;
    Session& operator=(const Session&)=delete;
    void Start(bool includeApplicationPaths=false);
    void SetRules(const std::vector<ANF_RULE>&); // Atomic replacement, <=64 rules.
    std::vector<ANF_EVENT> Read();               // Nonblocking, <=64 ALE events.
    ANF_STATUS Status() const;
    void Stop() noexcept;                      // Also automatic on destruction.
};
}
#endif
#endif
