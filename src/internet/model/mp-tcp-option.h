
#ifndef MP_TCP_OPTION_H
#define MP_TCP_OPTION_H

#include "ns3/tcp-option.h"
#include "ns3/ipv4-address.h"
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
  private:
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
  private:
    uint32_t m_senderToken;
    u_int8_t m_addrId;

};

class MpTcpOptionAdress : public TcpOption
{
  public:
    MpTcpOptionAdress();
    MpTcpOptionAdress();
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
    u_int8_t m_addrId;

};

} // namespace ns3
#endif