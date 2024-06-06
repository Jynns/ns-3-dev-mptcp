// #include "ns3/mp-tcp-socket-base.h"

#include "mp-tcp-socket-base.h"

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
    NS_LOG_UNCOND("Connect -> SegmentSize: " << sFlow->MSS << " segmentSize: " << segmentSize
                                             << "SendingBufferSize: " << sendingBuffer.bufMaxSize);

    // This is master subsocket (master subflow) then its endpoint is the same as connection
    // endpoint.
    sFlow->m_endPoint = m_endPoint;
    subflows.insert(subflows.end(), sFlow);
    //  m_tcp->m_sockets.push_back(this); //TMP REMOVE

    sFlow->rtt->Reset(); // Dangerous ?!?!?! Not really?
    sFlow->cnTimeout = m_cnTimeout;
    sFlow->cnRetries = m_synRetries;
    sFlow->m_synCount = sFlow->cnRetries;

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

void
MpTcpSocketBase::SendEmptyPacket(uint8_t sFlowIdx, uint8_t flags)
{
    NS_LOG_FUNCTION(this << (int)sFlowIdx);
    Ptr<MpTcpSubFlow> sFlow = subflows[sFlowIdx];

    SequenceNumber32 seq = SequenceNumber32(sFlow->TxSeqNumber);

    if (sFlow->m_endPoint == 0)
    {
        NS_FATAL_ERROR("Failed to send empty packet due to null subflow's endpoint");
        NS_LOG_WARN("Failed to send empty packet due to null subflow's endpoint");
        return;
    }

    if (flags & TcpHeader::FIN)
    {
        // flags |= TcpHeader::ACK;
        if (sFlow->maxSeqNb != sFlow->TxSeqNumber - 1)
        {
            NS_ASSERT(client);
            seq = sFlow->maxSeqNb + 1;
        }
    }
    else if (m_state == FIN_WAIT_1 || m_state == LAST_ACK || m_state == CLOSING)
    {
        ++seq;
    }

    // call to socket base function; senseless since we would have to modify almost every line
    // SendEmptyPacket(flags);
    TcpHeader header;
    header.SetSourcePort(sFlow->sPort);
    header.SetDestinationPort(sFlow->dPort);
    header.SetFlags(flags);
    header.SetSequenceNumber(seq);

    header.SetAckNumber(SequenceNumber32(sFlow->RxSeqNumber));
    header.SetWindowSize(AdvertisedWindowSize());

    bool hasSyn = flags & TcpHeader::SYN;
    bool hasFin = flags & TcpHeader::FIN;
    bool isAck = flags == TcpHeader::ACK;

    // RTO = srtt + 4* rttvar; here the og implementation from socket-base
    ns3::Time RTO =
        Max(sFlow->rtt->GetEstimate() + Max(m_clockGranularity, sFlow->rtt->GetVariation() * 4),
            m_minRto);

    if (hasSyn)
    {
        if (sFlow->m_synCount == 0)
        { // No more connection retries, give up
            cout << "[" << m_node->GetId() << "]{" << flowId << "}(" << flowType << ")"
                 << sFlow->m_synCount << endl;
            NS_LOG_UNCOND(Simulator::Now().GetSeconds()
                          << " [" << m_node->GetId() << "] (" << (int)sFlow->routeId
                          << ") SendEmptyPacket(" << TcpFlagPrinter(flags)
                          << ") hasSyn -> Connection failed."
                          << " Subflow's state: " << TcpStateName[sFlow->state]
                          << " Connection's state: " << TcpStateName[m_state] << " NumSubflows: "
                          << subflows.size() << " SendingBuffer: " << sendingBuffer.PendingData()
                          << " SubflowBufferSize: " << sFlow->mapDSN.size());

            // If intial subflow stuck on establishing a connection then close entire endpoint!
            if (subflows.size() == 1)
            { // If there is only one subflow we can safely tear down entire connection
                CloseAndNotifyAllSubflows();
                return;
            }

            CloseAndNotify(sFlow->routeId); // what if only one subflow failed to connect??
            return;
        }
        else
        { // Exponential backoff of connection time out
            int backoffCount = 0x1 << (sFlow->cnRetries - sFlow->m_synCount);
            RTO = Seconds(sFlow->cnTimeout.GetSeconds() * backoffCount);
            sFlow->m_synCount = sFlow->m_synCount - 1;
            NS_LOG_UNCOND(Simulator::Now().GetSeconds()
                          << " [" << m_node->GetId() << "] (" << (int)sFlow->routeId << ") "
                          << flowType << " SendEmptyPacket -> backoffCount: " << backoffCount
                          << " RTO: " << RTO.GetSeconds() << " cnTimeout: "
                          << sFlow->cnTimeout.GetSeconds() << " m_synCount: " << sFlow->m_synCount);
        }
        // TODO the og implementation calls here update RTT history; UpdateRttHistory m_history
    }
    if (((sFlow->state == SYN_SENT) || (sFlow->state == SYN_RCVD && mpEnabled == true)) &&
        mpSendState == MP_NONE)
    {
        mpSendState = MP_MPC; // This state means MP_MPC is sent
        do
        {                        // Prevent repetition of localToken to a node
            localToken = rand(); // Random Local Token
        } while (m_tcp->m_TokenMap.count(localToken) != 0 || localToken == 0);
        NS_ASSERT(m_tcp->m_TokenMap.count(localToken) == 0 && localToken != 0);
        header.AddOptMPC(OPT_MPC, localToken); // Adding MP_CAPABLE & Token to TCP option (5 Bytes)
        olen += 5;
        m_tcp->m_TokenMap[localToken] = m_endPoint;
        // m_tcp->m_TokenMap.insert(std::make_pair(localToken, m_endPoint))
        /*NS_LOG_UNCOND(
            "[" << m_node->GetId() << "] (" << (int)sFlow->routeId
                << ") SendEmptyPacket -> LOCALTOKEN is mapped
                   to connection endpoint->" << localToken << "->" << m_endPoint << " TokenMapsSize
            : "<<
              m_tcp->m_TokenMap.size()); OUT*/
    }
    else if ((sFlow->state == SYN_SENT && hasSyn &&
              sFlow->routeId ==
                  0) /* || (sFlow->state == SYN_RCVD && hasSyn && sFlow->routeId == 0)*/)
    {
        // header.AddOptMPC(OPT_MPC, localToken); // Adding MP_CAPABLE & Token to TCP option (5
        // Bytes) olen += 5;
        NS_LOG_INFO("unimplemented");
    }
    else if (sFlow->state == SYN_SENT && hasSyn && sFlow->routeId != 0)
    {
        // header.AddOptJOIN(OPT_JOIN, remoteToken, 0); // addID should be zero?
        // olen += 6;
        NS_LOG_INFO("unimplemented");
    }
    /*
    uint8_t plen = (4 - (olen % 4)) % 4;
    olen = (olen + plen) / 4;
    hlen = 5 + olen;
    header.SetLength(hlen);
    header.SetOptionsLength(olen);
    header.SetPaddingLength(plen);*/

    // m_tcp->SendPacket(p, header, sFlow->sAddr, sFlow->dAddr, FindOutputNetDevice(sFlow->sAddr));
    //  sFlow->rtt->SentSeq (sFlow->TxSeqNumber, 1);           // notify the RTT

    if (sFlow->retxEvent.IsExpired() && (hasFin || hasSyn) && !isAck)
    { // Retransmit SYN / SYN+ACK / FIN / FIN+ACK to guard against lost
        // RTO = sFlow->rtt->RetransmitTimeout();
        // sFlow->retxEvent =
        //    Simulator::Schedule(RTO, &MpTcpSocketBase::SendEmptyPacket, this, sFlowIdx, flags);
        if (hasSyn)
        {
            // cout << this << " ["<< m_node->GetId() << "]("<<(int)sFlowIdx <<") SendEmptyPacket ->
            // "<< TcpFlagPrinter(flags)<< " ReTxTimer set for SYN / SYN+ACK now " << Simulator::Now
            // ().GetSeconds () << " Expire at " << (Simulator::Now () + RTO).GetSeconds () << "
            // RTO: " << RTO.GetSeconds() << " FlowType: " << flowType << " Header: "<< header <<
            // endl;

            NS_LOG_INFO("unimplemented");
            // TODO
            /*NS_LOG_UNCOND(
                this << " [" << m_node->GetId() << "](" << (int)sFlowIdx << ") SendEmptyPacket -> "
                     << TcpFlagPrinter(flags) << " ReTxTimer set for SYN / SYN+ACK now "
                     << Simulator::Now().GetSeconds() << " Expire at "
                     << (Simulator::Now() + RTO).GetSeconds() << " RTO: " << RTO.GetSeconds()
                     << " FlowType: " << flowType << " Header: " << header);*/
        }
        if (hasFin)
        {
            /*NS_LOG_UNCOND(
                this << " [" << m_node->GetId() << "](" << (int)sFlowIdx << ") SendEmptyPacket -> "
                     << TcpFlagPrinter(flags) << " ReTxTimer set for FIN / FIN+ACK now "
                     << Simulator::Now().GetSeconds() << " Expire at "
                     << (Simulator::Now() + RTO).GetSeconds() << " RTO: " << RTO.GetSeconds()
                     << " FlowType: " << flowType << " Header: " << header);*/
            NS_LOG_INFO("unimplemented");
        }
    }

    // if (!isAck)
    // NS_LOG_INFO("(" << (int)sFlowIdx << ") SendEmptyPacket-> " << header
    //                << " Length: " << (int)header.GetLength());
}

bool
MpTcpSocketBase::IsThereRoute(Ipv4Address src, Ipv4Address dst)
{
    NS_LOG_FUNCTION(this << src << dst);
    return true;
    /*
    bool found = false;
    // Look up the source address
  //  Ptr<Ipv4> ipv4 = m_node->GetObject<Ipv4>();
    Ptr<Ipv4L3Protocol> ipv4 = m_node->GetObject<Ipv4L3Protocol>();
    if (ipv4->GetRoutingProtocol() != 0)
      {
        Ipv4Header l3Header;
        Socket::SocketErrno errno_;
        Ptr<Ipv4Route> route;
        //.....................................................................................
        //NS_LOG_INFO("----------------------------------------------------");NS_LOG_INFO("IsThereRoute()
  -> src: " << src << " dst: " << dst);
        // Get interface number from IPv4Address via ns3::Ipv4::GetInterfaceForAddress(Ipv4Address
  address); int32_t interface = ipv4->GetInterfaceForAddress(src);        // Morteza uses sign
  integers Ptr<Ipv4Interface> v4Interface = ipv4->GetRealInterfaceForAddress(src); Ptr<NetDevice>
  v4NetDevice = v4Interface->GetDevice();
        //PrintIpv4AddressFromIpv4Interface(v4Interface, interface);
        NS_ASSERT_MSG(interface != -1, "There is no interface object for the the src address");
        // Get NetDevice from Interface via ns3::Ipv4::GetNetDevice(uint32_t interface);
        Ptr<NetDevice> oif = ipv4->GetNetDevice(interface);
        NS_ASSERT(oif == v4NetDevice);

        //.....................................................................................
        l3Header.SetSource(src);
        l3Header.SetDestination(dst);
        route = ipv4->GetRoutingProtocol()->RouteOutput(Ptr<Packet>(), l3Header, oif, errno_);
        if ((route != 0)*/
    /* && (src == route->GetSource())*/ /*)
{
NS_LOG_DEBUG ("IsThereRoute -> Route from src "<< src << " to dst " << dst << " oit ["<<
oif->GetIfIndex()<<"], exist  Gateway: " << route->GetGateway()); found = true;
}
else
{
NS_LOG_DEBUG ("IsThereRoute -> No Route from srcAddr "<< src << " to dstAddr " << dst << " oit
["<<oif->GetIfIndex()<<"], exist Gateway: " << route->GetGateway());
}
}
return found;
*/
}

string
MpTcpSocketBase::TcpFlagPrinter(uint8_t flag)
{
    ostringstream oss;
    oss << "[";
    if (flag & TcpHeader::SYN)
        oss << " SYN ";
    if (flag & TcpHeader::FIN)
        oss << " FIN ";
    if (flag & TcpHeader::ACK)
        oss << " ACK ";
    if (flag & TcpHeader::RST)
        oss << " RST ";
    if (flag & TcpHeader::NONE)
        oss << " NONE";
    oss << "]";
    string tmp = oss.str();
    oss.str("");
    return tmp;
}

void
MpTcpSocketBase::CloseAndNotifyAllSubflows()
{
    NS_LOG_UNCOND(Simulator::Now().GetSeconds()
                  << " [" << m_node->GetId()
                  << "] CloseAndNotifyAllSubflows -> subflowSize: " << subflows.size());
    // Change state of all subflow to CLOSED then call to CloseAndNotify(sFlowIdx)
    for (uint32_t i = 0; i < subflows.size(); i++)
    {
        // subflows[i]->state = CLOSED;
        CloseAndNotify(subflows[i]->routeId);
    }
}

void
MpTcpSocketBase::CloseAndNotify(uint8_t sFlowIdx)
{
    NS_LOG_FUNCTION(this << (int)sFlowIdx);
    Ptr<MpTcpSubFlow> sFlow = subflows[sFlowIdx];
    //  if (!m_closeNotified)
    //    {
    //      NotifyNormalClose();
    //    }
    if (sFlow->state != TIME_WAIT)
    {
        NS_LOG_INFO("(" << (int)sFlowIdx << ") CloseAndNotify -> DeallocateEndPoint()");
        DeallocateEndPoint(sFlowIdx);
    }
    NS_LOG_INFO("(" << (int)sFlowIdx
                    << ") CloseAndNotify -> CancelAllTimers() and change the state");
    // m_closeNotified = true;
    CancelAllTimers(sFlowIdx);
    NS_LOG_INFO("(" << (int)sFlowIdx << ") " << TcpStateName[sFlow->state]
                    << " -> CLOSED {CloseAndNotify}");
    sFlow->state = CLOSED; // Can we remove closed subflow from subflow container????
    CloseMultipathConnection();
}

void
MpTcpSocketBase::DeallocateEndPoint(uint8_t sFlowIdx)
{
    NS_LOG_FUNCTION(this << (int)sFlowIdx);
    Ptr<MpTcpSubFlow> sFlow = subflows[sFlowIdx];
    // Master subflow would be closed when all other slave's subflows are closed.
    if (sFlowIdx == 0)
    {
        NS_LOG_INFO("(" << (int)sFlowIdx
                        << ") DeallocateEndPoint -> Master Subflow want to deallocate its "
                           "endpoint, call on CloseMultipathConnection()");
        CloseMultipathConnection();
    }
    // Slave's subflows
    else
    {
        if (sFlow->m_endPoint != 0)
        {
            NS_LOG_INFO("Salve subflow (" << (int)sFlowIdx << ") is deallocated its endpoint");
            sFlow->m_endPoint->SetDestroyCallback(MakeNullCallback<void>());
            m_tcp->DeAllocate(sFlow->m_endPoint);
            sFlow->m_endPoint = 0;
            CancelAllTimers(sFlowIdx);
        }
    }
}

bool
MpTcpSocketBase::CloseMultipathConnection()
{
    NS_LOG_FUNCTION_NOARGS();
    bool closed = false;
    uint32_t cpt = 0;
    for (uint32_t i = 0; i < subflows.size(); i++)
    {
        NS_LOG_LOGIC("Subflow (" << i << ") TxSeqNb (" << subflows[i]->TxSeqNumber
                                 << ") RxSeqNb = " << subflows[i]->RxSeqNumber << " highestAck ("
                                 << subflows[i]->highestAck << ") maxSeqNb ("
                                 << subflows[i]->maxSeqNb << ")");

        if (subflows[i]->state == CLOSED)
            cpt++;
        if (subflows[i]->state == TIME_WAIT)
        {
            NS_LOG_INFO("(" << (int)subflows[i]->routeId << ") " << TcpStateName[subflows[i]->state]
                            << " -> CLOSED {CloseMultipathConnection}");
            subflows[i]->state = CLOSED;
            cpt++;
        }
    }
    if (cpt == subflows.size())
    {
        if (m_state == ESTABLISHED && client) // We could remove client ... it should work but it
                                              // generate plots for receiver as well.
        {
            NS_LOG_INFO("CloseMultipathConnection -> GENERATE PLOTS SUCCESSFULLY -> HoOoOrA  pAck: "
                        << pAck);
            //          GenerateCWNDPlot();
            //          GenerateSendvsACK();
            //          GeneratePlots();
        }
        if (m_state != CLOSED)
        {
            NS_LOG_UNCOND(Simulator::Now().GetSeconds()
                          << "[" << m_node->GetId()
                          << "] CloseMultipathConnection -> MPTCP connection is closed {" << this
                          << "}, m_state: " << TcpStateName[m_state] << " -> CLOSED"
                          << " CurrentSubflow (" << (int)currentSublow
                          << ") SubflowsSize: " << subflows.size());
            m_state = CLOSED;
            NotifyNormalClose();
            m_endPoint->SetDestroyCallback(
                MakeNullCallback<void>()); // Remove callback to destroy()
            m_tcp->DeAllocate(m_endPoint); // Deallocating the endPoint
            m_endPoint = 0;
            if (subflows.size() > 0)
                subflows[0]->m_endPoint = 0;
            m_tcp->RemoveSocket(this);
            // m_tcp->RemoveLocalToken(localToken);
            /*std::vector<Ptr<TcpSocketBase> >::iterator it = std::find(m_tcp->m_sockets.begin(),
            m_tcp->m_sockets.end(), this); m_tcp->m_sockets if (it != m_tcp->m_sockets.end())
              {
                m_tcp->m_sockets.erase(it);
              }*/
            CancelAllSubflowTimers();
        }
    }
    return closed;
}

void
MpTcpSocketBase::CancelAllSubflowTimers(void)
{
    NS_LOG_FUNCTION_NOARGS();
    for (uint32_t i = 0; i < subflows.size(); i++)
    {
        Ptr<MpTcpSubFlow> sFlow = subflows[i];
        if (sFlow->state != CLOSED)
        {
            sFlow->retxEvent.Cancel();
            sFlow->m_lastAckEvent.Cancel();
            sFlow->m_timewaitEvent.Cancel();
            NS_LOG_INFO("CancelAllSubflowTimers() -> Subflow:" << sFlow->routeId);
        }
    }
}

void
MpTcpSocketBase::CancelAllTimers(uint8_t sFlowIdx)
{
    NS_LOG_FUNCTION((int)sFlowIdx);
    Ptr<MpTcpSubFlow> sFlow = subflows[sFlowIdx];
    sFlow->retxEvent.Cancel();
    sFlow->m_lastAckEvent.Cancel();
    sFlow->m_timewaitEvent.Cancel();
    NS_LOG_LOGIC("(" << (int)sFlow->routeId << ")" << "CancelAllTimers");
}

} // namespace ns3
