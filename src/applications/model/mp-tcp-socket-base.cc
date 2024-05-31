#include "ns3/mp-tcp-socket-base.h"

NS_LOG_COMPONENT_DEFINE("MpTcpSocketBase");
using namespace std;
namespace ns3
{
NS_OBJECT_ENSURE_REGISTERED(MpTcpSocketBase);

TypeId
MpTcpSocketBase::GetTypeId()
{
  static TypeId tid = TypeId("ns3::MpTcpSocketBase")
      .SetParent<TcpSocketBase>()
      .AddConstructor<MpTcpSocketBase>()
      .AddAttribute("CongestionControl",
                    "Congestion control algorithm",
          EnumValue(Linked_Increases),
          MakeEnumAccessor(&MpTcpSocketBase::SetCongestionCtrlAlgo),
          MakeEnumChecker(Uncoupled_TCPs,   "Uncoupled_TCPs",
                          Fully_Coupled,    "Fully_Coupled",
                          RTT_Compensator,  "RTT_Compensator",
                          Linked_Increases, "Linked_Increases",
                          COUPLED_INC,      "COUPLED_INC",
                          COUPLED_EPSILON,  "COUPLED_EPSILON",
                          COUPLED_SCALABLE_TCP, "COUPLED_SCALABLE_TCP",
                          COUPLED_FULLY, "COUPLED_FULLY",
                          UNCOUPLED, "UNCOUPLED"))

      .AddAttribute("SchedulingAlgorithm",
                    "Algorithm for data distribution between sub-flows",
          EnumValue(Round_Robin),
          MakeEnumAccessor(&MpTcpSocketBase::SetSchedulingAlgo),
          MakeEnumChecker(Round_Robin, "Round_Robin"))

      .AddAttribute("PathManagement",
                     "Mechanism for establishing new sub-flows",
          EnumValue(FullMesh),
          MakeEnumAccessor(&MpTcpSocketBase::SetPathManager),
          MakeEnumChecker(Default,"Default",
                          FullMesh, "FullMesh",
                          NdiffPorts, "NdiffPorts"))

      .AddAttribute("MaxSubflows",
                    "Maximum number of sub-flows per each mptcp connection",
          UintegerValue(8),
          MakeUintegerAccessor(&MpTcpSocketBase::maxSubflows),
          MakeUintegerChecker<uint8_t>())

     .AddAttribute("RandomGap",
          "Random gap between subflows setup",
          UintegerValue(50),
          MakeUintegerAccessor(&MpTcpSocketBase::m_rGap),
          MakeUintegerChecker<uint32_t>())

      /*.AddAttribute("Subflows",
                    "The list of sub-flows associated to this protocol.",
          ObjectVectorValue(),
          MakeObjectVectorAccessor(&MpTcpSocketBase::subflows),
          MakeObjectVectorChecker<MpTcpSocketBase>())*/

      .AddAttribute ("ShortFlowTCP", "Use TCP for short flows",
          BooleanValue (false),
          MakeBooleanAccessor (&MpTcpSocketBase::m_shortFlowTCP),
          MakeBooleanChecker())

      .AddAttribute ("AlphaPerAck", " Update alpha per ACK ",
          BooleanValue (false),
          MakeBooleanAccessor (&MpTcpSocketBase::m_alphaPerAck),
          MakeBooleanChecker())

      .AddAttribute ("ShortPlotting", " Activate large flow plotting ",
          BooleanValue (false),
          MakeBooleanAccessor (&MpTcpSocketBase::m_shortPlotting),
          MakeBooleanChecker())

      .AddAttribute ("LargePlotting", " Activate short flow plotting ",
          BooleanValue (false),
          MakeBooleanAccessor (&MpTcpSocketBase::m_largePlotting),
          MakeBooleanChecker());

  return tid;
}

MpTcpSocketBase::MpTcpSocketBase()
    //subflows(0), localAddrs(0), remoteAddrs(0)
//:
//    m_node(node), m_tcp(node->GetObject<TcpL4Protocol>()), mpState(MP_NONE), mpSendState(MP_NONE), mpRecvState(MP_NONE), mpEnabled(false), addrAdvertised(
//        false), mpTokenRegister(false), subflows(0), localAddrs(0), remoteAddrs(0), lastUsedsFlowIdx(0), totalCwnd(0), localToken(0), remoteToken(0), client(
//        false), server(false), remoteRecvWnd(1), segmentSize(0), nextTxSequence(1), nextRxSequence(1)
{
  NS_LOG_FUNCTION(this);
  //m_node = node;
  //m_tcp = node->GetObject<TcpL4Protocol>();
}

MpTcpSocketBase::MpTcpSocketBase(Ptr<Node> node)
    //subflows(0), localAddrs(0), remoteAddrs(0)
//:
//    m_node(node), m_tcp(node->GetObject<TcpL4Protocol>()), mpState(MP_NONE), mpSendState(MP_NONE), mpRecvState(MP_NONE), mpEnabled(false), addrAdvertised(
//        false), mpTokenRegister(false), subflows(0), localAddrs(0), remoteAddrs(0), lastUsedsFlowIdx(0), totalCwnd(0), localToken(0), remoteToken(0), client(
//        false), server(false), remoteRecvWnd(1), segmentSize(0), nextTxSequence(1), nextRxSequence(1)
{
  NS_LOG_FUNCTION(this);
  //m_node = node;
  //m_tcp = node->GetObject<TcpL4Protocol>();
}

MpTcpSocketBase::~MpTcpSocketBase(void)
{
  NS_LOG_FUNCTION(this);
  /*
   * Upon Bind, an Ipv4Endpoint is allocated and set to m_endPoint, and
   * DestroyCallback is set to TcpSocketBase::Destroy. If we called
   * m_tcp->DeAllocate, it will destroy its Ipv4EndpointDemux::DeAllocate,
   * which in turn destroys my m_endPoint, and in turn invokes
   * TcpSocketBase::Destroy to nullify m_node, m_endPoint, and m_tcp.
   */
}

void
MpTcpSocketBase::SetCongestionCtrlAlgo(CongestionCtrl_t ccalgo)
{
  m_algocc = ccalgo;
}

void 
MpTcpSocketBase::SetSchedulingAlgo(DataDistribAlgo_t ddalgo){
    m_scheduler = ddalgo;
}

void
MpTcpSocketBase::SetPathManager(PathManager_t pManagerMode)
{
  m_pathManager = pManagerMode;
}


}
