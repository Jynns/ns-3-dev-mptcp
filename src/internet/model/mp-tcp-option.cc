#include "mp-tcp-option.h"

namespace ns3
{
NS_LOG_COMPONENT_DEFINE("MpTcpOption");

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

MpTcpOptionAdress::MpTcpOptionAdress()
{
}

MpTcpOptionAdress::MpTcpOptionAdress(uint8_t addrID, ns3::Ipv4Address m_addr): m_addr{m_addr}, m_addrId{addrID}
{
}

MpTcpOptionAdress::~MpTcpOptionAdress()
{
}

TypeId
MpTcpOptionAdress::GetTypeId()
{
    static TypeId tid = TypeId("ns3::MpTcpOptionAdress")
                            .SetParent<TcpOption>()
                            .SetGroupName("Internet")
                            .AddConstructor<MpTcpOptionAdress>();
    return tid;
}

TypeId
MpTcpOptionAdress::GetInstanceTypeId() const
{
    return GetTypeId();
}

void
MpTcpOptionAdress::Print(std::ostream& os) const
{
    os << "MpTcpOptionAdress addrID" << m_addrId << " addr " << m_addr;
}

void
MpTcpOptionAdress::Serialize(Buffer::Iterator start) const
{
    start.WriteU8(m_addrId);
    start.WriteHtonU32(m_addr.Get());
}

uint32_t
MpTcpOptionAdress::Deserialize(Buffer::Iterator start)
{
    m_addrId = start.ReadU8();
    m_addr = Ipv4Address(start.ReadNtohU32());
    return GetSerializedSize();
}

uint8_t
MpTcpOptionAdress::GetKind() const
{
    return TcpOption::Kind::MP_ADDR;
}

uint32_t
MpTcpOptionAdress::GetSerializedSize() const
{
    return 5;
}

MpTcpOptionDataSeqMapping::MpTcpOptionDataSeqMapping()
{
}

MpTcpOptionDataSeqMapping::MpTcpOptionDataSeqMapping(uint64_t dSeqNum,
                                                     uint16_t dLevelLength,
                                                     uint32_t sfSeqNum):m_dSeqNum{dSeqNum}, m_dLevelLength{dLevelLength}, m_sfSeqNum{sfSeqNum}
{
}

MpTcpOptionDataSeqMapping::~MpTcpOptionDataSeqMapping()
{
}

TypeId
MpTcpOptionDataSeqMapping::GetTypeId()
{
    static TypeId tid = TypeId("ns3::MpTcpOptionDataSeqMapping")
                            .SetParent<TcpOption>()
                            .SetGroupName("Internet")
                            .AddConstructor<MpTcpOptionDataSeqMapping>();
    return tid;
}

TypeId
MpTcpOptionDataSeqMapping::GetInstanceTypeId() const
{
    return GetTypeId();
}

void
MpTcpOptionDataSeqMapping::Print(std::ostream& os) const
{
    os << "MpTcpOptionDataSeqMapping "  
}

void
MpTcpOptionDataSeqMapping::Serialize(Buffer::Iterator start) const
{
    start.WriteU64(m_dSeqNum);
    start.WriteHtonU16(m_dLevelLength);
    start.WriteHtonU32(m_sfSeqNum);
}

uint32_t
MpTcpOptionDataSeqMapping::Deserialize(Buffer::Iterator start)
{
    m_dSeqNum = start.ReadU64();
    m_dLevelLength = start.ReadNtohU16();
    m_sfSeqNum = start.ReadNtohU32(); 
    return GetSerializedSize();
}

uint8_t
MpTcpOptionDataSeqMapping::GetKind() const
{
    return TcpOption::Kind::MP_DSN;
}

uint32_t
MpTcpOptionDataSeqMapping::GetSerializedSize() const
{
    return 14;
}

} // namespace ns3
