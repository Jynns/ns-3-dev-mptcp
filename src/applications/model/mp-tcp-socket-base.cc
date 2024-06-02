#include "ns3/mp-tcp-socket-base.h"

NS_LOG_COMPONENT_DEFINE("MpTcpSocketBase");
using namespace std;

namespace ns3
{
NS_OBJECT_ENSURE_REGISTERED(MpTcpSocketBase);

TypeId
MpTcpSocketBase::GetTypeId()
{
    static TypeId tid =
        TypeId("ns3::MpTcpSocketBase")
            .SetParent<TcpSocketBase>()
            .AddConstructor<MpTcpSocketBase>()
            .AddAttribute("CongestionControl",
                          "Congestion control algorithm",
                          EnumValue(Linked_Increases),
                          MakeEnumAccessor(&MpTcpSocketBase::SetCongestionCtrlAlgo),
                          MakeEnumChecker(Uncoupled_TCPs,
                                          "Uncoupled_TCPs",
                                          Fully_Coupled,
                                          "Fully_Coupled",
                                          RTT_Compensator,
                                          "RTT_Compensator",
                                          Linked_Increases,
                                          "Linked_Increases",
                                          COUPLED_INC,
                                          "COUPLED_INC",
                                          COUPLED_EPSILON,
                                          "COUPLED_EPSILON",
                                          COUPLED_SCALABLE_TCP,
                                          "COUPLED_SCALABLE_TCP",
                                          COUPLED_FULLY,
                                          "COUPLED_FULLY",
                                          UNCOUPLED,
                                          "UNCOUPLED"))

            .AddAttribute("SchedulingAlgorithm",
                          "Algorithm for data distribution between sub-flows",
                          EnumValue(Round_Robin),
                          MakeEnumAccessor(&MpTcpSocketBase::SetSchedulingAlgo),
                          MakeEnumChecker(Round_Robin, "Round_Robin"))

            .AddAttribute(
                "PathManagement",
                "Mechanism for establishing new sub-flows",
                EnumValue(FullMesh),
                MakeEnumAccessor(&MpTcpSocketBase::SetPathManager),
                MakeEnumChecker(Default, "Default", FullMesh, "FullMesh", NdiffPorts, "NdiffPorts"))

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

            .AddAttribute("ShortFlowTCP",
                          "Use TCP for short flows",
                          BooleanValue(false),
                          MakeBooleanAccessor(&MpTcpSocketBase::m_shortFlowTCP),
                          MakeBooleanChecker())

            .AddAttribute("AlphaPerAck",
                          " Update alpha per ACK ",
                          BooleanValue(false),
                          MakeBooleanAccessor(&MpTcpSocketBase::m_alphaPerAck),
                          MakeBooleanChecker())

            .AddAttribute("ShortPlotting",
                          " Activate large flow plotting ",
                          BooleanValue(false),
                          MakeBooleanAccessor(&MpTcpSocketBase::m_shortPlotting),
                          MakeBooleanChecker())

            .AddAttribute("LargePlotting",
                          " Activate short flow plotting ",
                          BooleanValue(false),
                          MakeBooleanAccessor(&MpTcpSocketBase::m_largePlotting),
                          MakeBooleanChecker());

    return tid;
}

MpTcpSocketBase::MpTcpSocketBase()
    : // TODO subflows(0),
      localAddrs(0),
      remoteAddrs(0)
//    m_node(node), m_tcp(node->GetObject<TcpL4Protocol>()), mpState(MP_NONE), mpSendState(MP_NONE),
//    mpRecvState(MP_NONE), mpEnabled(false), addrAdvertised(
//        false), mpTokenRegister(false), subflows(0), localAddrs(0), remoteAddrs(0),
//        lastUsedsFlowIdx(0), totalCwnd(0), localToken(0), remoteToken(0), client( false),
//        server(false), remoteRecvWnd(1), segmentSize(0), nextTxSequence(1), nextRxSequence(1)
{
    NS_LOG_FUNCTION(this);
    mpSendState = MP_NONE;
    mpRecvState = MP_NONE;
    mpEnabled = false;
    addrAdvertised = false;
    mpTokenRegister = false;
    lastUsedsFlowIdx = 0;
    totalCwnd = 0;
    localToken = 0;
    remoteToken = 0;
    client = false;
    server = false;
    remoteRecvWnd = 1;
    segmentSize = 0;
    nextTxSequence = 1;
    nextRxSequence = 1;

    fLowStartTime = 0;
    FullAcks = 0;
    pAck = 0;
    TimeOuts = 0;
    FastReTxs = 0;
    FastRecoveries = 0;
    flowCompletionTime = true;
    // TxBytes = 0;
    flowType = "NULL";
    outputFileName = "NULL";

    alpha = 1; // alpha is 1 by default
    _e = 1;    // epsilon 1 by default
    a = A_SCALE;

    //"remove" callback from socket libary
    Callback<void, Ptr<Socket>> vPS = MakeNullCallback<void, Ptr<Socket>>();
    Callback<void, Ptr<Socket>, const Address&> vPSA =
        MakeNullCallback<void, Ptr<Socket>, const Address&>();
    Callback<void, Ptr<Socket>, uint32_t> vPSUI = MakeNullCallback<void, Ptr<Socket>, uint32_t>();
    SetConnectCallback(vPS, vPS);
    SetDataSentCallback(vPSUI);
    SetSendCallback(vPSUI);
    SetRecvCallback(vPS);
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

/** Inhereted from Socket class: Bind socket to an end-point in MpTcpL4Protocol */
int
MpTcpSocketBase::Bind()
{
    NS_LOG_FUNCTION(this);
    client = true;

    m_endPoint = m_tcp->Allocate(); // Create endPoint with ephemeralPort.
    if (0 == m_endPoint)
    {
        m_errno = ERROR_ADDRNOTAVAIL;
        return -1;
    }
    // m_tcp->m_sockets.push_back(this); // We don't need it for now
    return SetupCallback();
}

int
MpTcpSocketBase::Bind(const Address& address)
{
    NS_LOG_FUNCTION(this << address);
    server = true;
    if (!InetSocketAddress::IsMatchingType(address))
    {
        m_errno = ERROR_INVAL;
        return -1;
    }

    InetSocketAddress transport = InetSocketAddress::ConvertFrom(address);
    Ipv4Address ipv4 = transport.GetIpv4();
    uint16_t port = transport.GetPort();

    // NS_ASSERT(GetBoundNetDevice() != nullptr );
    if (ipv4 == Ipv4Address::GetAny() && port == 0)
    {
        m_endPoint = m_tcp->Allocate();
    }
    else if (ipv4 == Ipv4Address::GetAny() && port != 0)
    { // Allocate with specific port
        m_endPoint = m_tcp->Allocate(GetBoundNetDevice(), port);
    }
    else if (ipv4 != Ipv4Address::GetAny() && port == 0)
    { // Allocate with specific ipv4 address
        m_endPoint = m_tcp->Allocate(ipv4);
    }
    else if (ipv4 != Ipv4Address::GetAny() && port != 0)
    { // Allocate with specific Ipv4 add:port
        m_endPoint = m_tcp->Allocate(GetBoundNetDevice(), ipv4, port);
    }
    else
    {
        NS_LOG_ERROR("Bind to specific add:port has failed!");
    }

    // m_tcp->m_sockets.push_back(this); // we don't need it for now
    NS_LOG_LOGIC("MpTcpSocketBase:Bind(addr) "
                 << this << " got an endpoint " << m_endPoint << " localAddr "
                 << m_endPoint->GetLocalAddress() << ":" << m_endPoint->GetLocalPort()
                 << " RemoteAddr " << m_endPoint->GetPeerAddress() << ":"
                 << m_endPoint->GetPeerPort());
    return SetupCallback();
}

int
MpTcpSocketBase::Connect(const Address& address)
{
    NS_LOG_FUNCTION(this << address);
    InetSocketAddress transport = InetSocketAddress::ConvertFrom(address);
    m_remoteAddress = transport.GetIpv4(); // MPTCP Connection remoteAddress
    m_remotePort = transport.GetPort();    // MPTCP Connection remotePort
    return Connect(m_remoteAddress, m_remotePort);
}

int
MpTcpSocketBase::Connect(Ipv4Address servAddr, uint16_t servPort)
{
    NS_LOG_FUNCTION(this << servAddr << servPort); //
    Ptr<MpTcpSubFlow> sFlow = CreateObject<MpTcpSubFlow>();
    sFlow->routeId = (subflows.size() == 0 ? 0 : subflows[subflows.size() - 1]->routeId + 1);
    sFlow->dAddr = servAddr;    // Assigned subflow destination address
    sFlow->dPort = servPort;    // Assigned subflow destination port
    m_remoteAddress = servAddr; // MPTCP Connection's remote address
    m_remotePort = servPort;    // MPTCP Connection's remote port

    if (m_endPoint == 0)
    {
        if (Bind() == -1) // Bind(), if there is no endpoint for this socket
        {
            NS_ASSERT(m_endPoint == 0);
            return -1; // Bind() failed.
        }
        // Make sure endpoint is created.
        NS_ASSERT(m_endPoint != 0);
    }
    // Set up remote addr:port for this endpoint as we knew it from Connect's parameters
    m_endPoint->SetPeer(servAddr, servPort);

    if (m_endPoint->GetLocalAddress() == "0.0.0.0")
    {
        // Find approapriate local address from the routing protocol for this endpoint.
        if (SetupEndpoint() != 0)
        { // Route to destination does not exist.
            return -1;
        }
    }
    else
    { // Make sure there is an route from source to destination. Source might be set wrongly.
        if ((IsThereRoute(m_endPoint->GetLocalAddress(), servAddr)) == false)
        {
            NS_LOG_INFO("Connect -> There is no route from "
                        << m_endPoint->GetLocalAddress() << " to " << m_endPoint->GetPeerAddress());
            // m_tcp->DeAllocate(m_endPoint); // this would fire up destroy function...
            return -1;
        }
    }

    // Set up subflow local addrs:port from endpoint
    sFlow->sAddr = m_endPoint->GetLocalAddress();
    sFlow->sPort = m_endPoint->GetLocalPort();
    sFlow->MSS = segmentSize;
    sFlow->cwnd = sFlow->MSS;
    NS_LOG_UNCOND("Connect -> SegmentSize: " << sFlow->MSS << " tcpSegmentSize: " << m_segmentSize
                                             << " segmentSize: " << segmentSize
                                             << "SendingBufferSize: " << sendingBuffer.bufMaxSize);

    // This is master subsocket (master subflow) then its endpoint is the same as connection
    // endpoint.
    sFlow->m_endPoint = m_endPoint;
    subflows.insert(subflows.end(), sFlow);
    //  m_tcp->m_sockets.push_back(this); //TMP REMOVE

    sFlow->rtt->Reset(); // Dangerous ?!?!?! Not really?
    sFlow->cnTimeout = m_cnTimeout;
    sFlow->cnRetries = m_cnRetries;
    sFlow->cnCount = sFlow->cnRetries;

    //  if (sFlow->state == CLOSED || sFlow->state == LISTEN || sFlow->state == SYN_SENT ||
    //  sFlow->state == LAST_ACK || sFlow->state == CLOSE_WAIT)
    //    { // send a SYN packet and change state into SYN_SENT
    NS_LOG_INFO("(" << (int)sFlow->routeId << ") " << TcpStateName[sFlow->state] << " -> SYN_SENT");
    m_state = SYN_SENT;
    sFlow->state = SYN_SENT; // Subflow state should be change first then SendEmptyPacket...
    SendEmptyPacket(sFlow->routeId, TcpHeader::SYN);
    currentSublow = sFlow->routeId; // update currentSubflow in case close just after 3WHS.
    NS_LOG_INFO(this << "  MPTCP connection is initiated (Sender): " << sFlow->sAddr << ":"
                     << sFlow->sPort << " -> " << sFlow->dAddr << ":" << sFlow->dPort
                     << " m_state: " << TcpStateName[m_state]);
    //    }
    //  else if (sFlow->state != TIME_WAIT)
    //    { // In states SYN_RCVD, ESTABLISHED, FIN_WAIT_1, FIN_WAIT_2, and CLOSING, an connection
    //      // exists. We send RST, tear down everything, and close this socket.
    //      NS_LOG_WARN(" Connect-> Can't open another connection as connection is exist -> RST need
    //      to be sent. Not yet implemented");
    //    SendRST ();
    //      CloseAndNotify ();
    //    }
    // For FlowCompletion time
    /*
     * I think FCT should not be started here as some flow's SYN might get drop.
     * It seems right to put flow start time when a flow has completed its 3WHS.
     */
    // fLowStartTime = Simulator::Now().GetSeconds();
    return 0;
}

void
MpTcpSocketBase::SetCongestionCtrlAlgo(CongestionCtrl_t ccalgo)
{
    m_algocc = ccalgo;
}

void
MpTcpSocketBase::SetSchedulingAlgo(DataDistribAlgo_t ddalgo)
{
    m_scheduler = ddalgo;
}

void
MpTcpSocketBase::SetPathManager(PathManager_t pManagerMode)
{
    m_pathManager = pManagerMode;
}

} // namespace ns3
