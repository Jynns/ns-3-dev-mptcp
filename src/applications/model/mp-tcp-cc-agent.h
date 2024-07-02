#ifndef MP_TCP_CC_AGENT_H
#define MP_TCP_CC_AGENT_H
#include "ns3/core-module.h"
#include "ns3/mp-tcp-subflow.h"
#include "ns3/object.h"


namespace ns3
{
class MpTcpSubFlow;
class CongestionInfo : public Object
{
  public: // methods
    CongestionInfo(){};
    ~CongestionInfo(){};

    static TypeId GetTypeId(void)
    {
        static TypeId tid =
            TypeId("ns3::CongestionInfo").SetParent<Object>().AddConstructor<CongestionInfo>();
        // TODO Add Accessor and move variables to private
        return tid;
    };

    void reset()
    {
        AckOrTimeout = 0;
        DupAck = 0;
        inflightAck = 0;
        lastCwndTO = -1; // hasn't happened yet
        lastCwndDA = -1;
        ratiolastCWNDTO = -1; // since no lastCWNDTO there shouldn't be a ratio
        ratiolastCWNDDA = -1; // since no lastCWNDDA there shouldn't be a ratio
        numberConsecutiveDup = 0;
        factorChain = 1;
    };

  public:
    bool AckOrTimeout;             //<! 0: TO; 1: ACK
    bool DupAck;                   //<! is it Dupack
    bool inflightAck;              //<! if the ack came from a packet that was in-flight during last
                                   // timeout/Dupack
    int32_t lastCwndTO;           //<! CWND before Lasttimeout
    int32_t lastCwndDA;           //<! CWND before DupAck
    float ratiolastCWNDTO;         //<! ratio between current and lastCwndTO
    float ratiolastCWNDDA;         //<! ratio between current and lastCwndDA
    uint32_t numberConsecutiveDup; //<! latest number of consecutive Dup Acks
    float factorChain = 1;         //<! updates since dupack resets on normal ack(not inflight)
};

class MpTcpCongestionControlAgent : public Object

{
  public:
    MpTcpCongestionControlAgent();
    ~MpTcpCongestionControlAgent();

    static TypeId GetTypeId(void);
    void virtual Infer(Ptr<MpTcpSubFlow> sflow,
                       Ptr<CongestionInfo> ccInfo); //<! performs the action if inference (ACK
                                                    //   or RTO) by updating subflow cwnd
};

} // namespace ns3

#endif