
#ifndef MP_TCP_OPTION_H
#define MP_TCP_OPTION_H

#include "ns3/ipv4-address.h"
#include "ns3/tcp-option.h"

/*
case MP_NONE:
    case MP_MPC:
    case MP_ADDR:
    case MP_JOIN:
    case MP_DSN:*/

namespace ns3
{

class MpTcpOptionNone : public TcpOption
{
  public:
    MpTcpOptionNone();
    ~MpTcpOptionNone() override;

    /**
     * \brief Get the type ID.
     * \return the object TypeId
     */
    static TypeId GetTypeId();
    TypeId GetInstanceTypeId() const override;

    void Print(std::ostream& os) const override;
    void Serialize(Buffer::Iterator start) const override;
    uint32_t Deserialize(Buffer::Iterator start) override;

    uint8_t GetKind() const override;
    uint32_t GetSerializedSize() const override;
};

class MpTcpOptionMultiPathCabable : public TcpOption
{
  public:
    MpTcpOptionMultiPathCabable();
    MpTcpOptionMultiPathCabable(uint32_t token);
    ~MpTcpOptionMultiPathCabable() override;

    /**
     * \brief Get the type ID.
     * \return the object TypeId
     */
    static TypeId GetTypeId();
    TypeId GetInstanceTypeId() const override;

    void Print(std::ostream& os) const override;
    void Serialize(Buffer::Iterator start) const override;
    uint32_t Deserialize(Buffer::Iterator start) override;

    uint8_t GetKind() const override;
    uint32_t GetSerializedSize() const override;

  public:
    uint32_t m_senderToken;
};

class MpTcpOptionJoin : public TcpOption
{
  public:
    MpTcpOptionJoin();
    MpTcpOptionJoin(uint32_t Token, uint8_t addrID);
    ~MpTcpOptionJoin() override;

    /**
     * \brief Get the type ID.
     * \return the object TypeId
     */
    static TypeId GetTypeId();
    TypeId GetInstanceTypeId() const override;

    void Print(std::ostream& os) const override;
    void Serialize(Buffer::Iterator start) const override;
    uint32_t Deserialize(Buffer::Iterator start) override;

    uint8_t GetKind() const override;
    uint32_t GetSerializedSize() const override;

  public:
    uint32_t m_senderToken;
    u_int8_t m_addrId;
};

class MpTcpOptionAdress : public TcpOption
{
  public:
    MpTcpOptionAdress();
    MpTcpOptionAdress(uint8_t addrID, ns3::Ipv4Address m_addr);
    ~MpTcpOptionAdress() override;

    /**
     * \brief Get the type ID.
     * \return the object TypeId
     */
    static TypeId GetTypeId();
    TypeId GetInstanceTypeId() const override;

    void Print(std::ostream& os) const override;
    void Serialize(Buffer::Iterator start) const override;
    uint32_t Deserialize(Buffer::Iterator start) override;

    uint8_t GetKind() const override;
    uint32_t GetSerializedSize() const override;

  private:
    ns3::Ipv4Address m_addr;
    uint8_t m_addrId;
};

class MpTcpOptionDataSeqMapping : public TcpOption
{
  public:
    MpTcpOptionDataSeqMapping();
    MpTcpOptionDataSeqMapping(uint64_t dSeqNum, uint16_t dLevelLength, uint32_t sfSeqNum);
    ~MpTcpOptionDataSeqMapping() override;

    /**
     * \brief Get the type ID.
     * \return the object TypeId
     */
    static TypeId GetTypeId();
    TypeId GetInstanceTypeId() const override;

    void Print(std::ostream& os) const override;
    void Serialize(Buffer::Iterator start) const override;
    uint32_t Deserialize(Buffer::Iterator start) override;

    uint8_t GetKind() const override;
    uint32_t GetSerializedSize() const override;

  private:
    uint64_t m_dSeqNum; 
    uint16_t m_dLevelLength; 
    uint32_t m_sfSeqNum;
};

} // namespace ns3
#endif