#include "mp-tcp-cc-agent.h"

namespace ns3
{
ns3::MpTcpCongestionControlAgent::MpTcpCongestionControlAgent()
{
}

ns3::MpTcpCongestionControlAgent::~MpTcpCongestionControlAgent()
{
}

TypeId
ns3::MpTcpCongestionControlAgent::GetTypeId(void)
{
    static TypeId tid = TypeId("ns3::MpTcpCongestionControlAgent")
                            .SetParent<Object>()
                            .AddConstructor<MpTcpCongestionControlAgent>();
    return tid;
}

void
MpTcpCongestionControlAgent::Infer(Ptr<MpTcpSubFlow> sflow, Ptr<CongestionInfo> ccInfo)
{
}
} // namespace ns3