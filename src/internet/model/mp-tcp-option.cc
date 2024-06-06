#include "mp-tcp-option.h"

namespace ns3
{
NS_LOG_COMPONENT_DEFINE("MpTcpOptionNone");

NS_OBJECT_ENSURE_REGISTERED(MpTcpOptionNone);

MpTcpOptionNone::MpTcpOptionNone()
{
}

MpTcpOptionNone::~MpTcpOptionNone()
{
}

TypeId
MpTcpOptionNone::GetTypeId()
{
    static TypeId tid = TypeId("ns3::MpTcpOptionNone")
                            .SetParent<TcpOption>()
                            .SetGroupName("Internet")
                            .AddConstructor<MpTcpOptionNone>();
    return tid;
}

TypeId
MpTcpOptionNone::GetInstanceTypeId() const
{
    return GetTypeId();
}

void
MpTcpOptionNone::Print(std::ostream& os) const
{
    os << "Explicitly no MP option";
}

void
MpTcpOptionNone::Serialize(Buffer::Iterator start) const
{
}

uint32_t
MpTcpOptionNone::Deserialize(Buffer::Iterator start)
{
    return 0;
}

uint8_t
MpTcpOptionNone::GetKind() const
{
    return TcpOption::Kind::MP_NONE;
}

uint32_t
MpTcpOptionNone::GetSerializedSize() const
{
    return 4;
}

//NS_LOG_COMPONENT_DEFINE("MpTcpOptionMultiPathCabable");

//NS_OBJECT_ENSURE_REGISTERED(MpTcpOptionMultiPathCabable);

MpTcpOptionMultiPathCabable::MpTcpOptionMultiPathCabable()
{
    m_senderToken = 0;
}

TypeId
MpTcpOptionMultiPathCabable::GetTypeId()
{
    static TypeId tid = TypeId("ns3::MpTcpOptionMultiPathCabable")
                            .SetParent<TcpOption>()
                            .SetGroupName("Internet")
                            .AddConstructor<MpTcpOptionMultiPathCabable>();
    return tid;
}

TypeId
MpTcpOptionMultiPathCabable::GetInstanceTypeId() const
{
    return GetTypeId();
}

void
MpTcpOptionMultiPathCabable::Print(std::ostream& os) const
{
    os << "Multipath capable option " << m_senderToken;
}

void
MpTcpOptionMultiPathCabable::Serialize(Buffer::Iterator start) const
{
    start.WriteHtonU32(m_senderToken);
}

uint32_t
MpTcpOptionMultiPathCabable::Deserialize(Buffer::Iterator start)
{
    m_senderToken = start.ReadNtohU32();
    return GetSerializedSize();
}

uint8_t
MpTcpOptionMultiPathCabable::GetKind() const
{
    return TcpOption::Kind::MP_MPC;
}

uint32_t
MpTcpOptionMultiPathCabable::GetSerializedSize() const
{
    return 4;
}

MpTcpOptionJoin::MpTcpOptionJoin()
{
}

MpTcpOptionJoin::MpTcpOptionJoin(uint32_t Token, uint8_t addrID): m_senderToken{Token}, m_addrId{addrID}
{}

MpTcpOptionJoin::~MpTcpOptionJoin()
{
}

TypeId
MpTcpOptionJoin::GetTypeId()
{
    static TypeId tid = TypeId("ns3::MpTcpOptionJoin")
                            .SetParent<TcpOption>()
                            .SetGroupName("Internet")
                            .AddConstructor<MpTcpOptionJoin>();
    return tid;
}

TypeId
MpTcpOptionJoin::GetInstanceTypeId() const
{
    return GetTypeId();
}

void
MpTcpOptionJoin::Print(std::ostream& os) const
{
    os << "MpTcpOptionJoin Token"<< m_senderToken << " addrID: " << m_addrId;
}

void
MpTcpOptionJoin::Serialize(Buffer::Iterator start) const
{
    start.WriteHtonU32(m_senderToken);
    start.WriteU8(m_addrId);
}

uint32_t
MpTcpOptionJoin::Deserialize(Buffer::Iterator start)
{
    m_senderToken = start.ReadNtohU32();
    m_addrId = start.ReadU8();
    return GetSerializedSize();
}

uint8_t
MpTcpOptionJoin::GetKind() const
{
    return TcpOption::Kind::MP_JOIN;
}

uint32_t
MpTcpOptionJoin::GetSerializedSize() const
{
    return 5;
}

} // namespace ns3
