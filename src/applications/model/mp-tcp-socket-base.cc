// #include "ns3/mp-tcp-socket-base.h"

#include "mp-tcp-socket-base.h"

#include "ns3/internet-module.h"

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
    a = 512;

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

int
MpTcpSocketBase::Listen(void)
{
    NS_LOG_FUNCTION(this);

    if (m_state != CLOSED)
    {
        m_errno = ERROR_INVAL;
        return -1;
    }

    // MPTCP connection state is LISTEN
    m_state = LISTEN;
    return 0;
}

int
MpTcpSocketBase::Close(void)
{
    NS_LOG_FUNCTION(this);
    if (subflows.size() > 0)
    {
        { // This block could be removed...
            if (subflows.size() == 1)
                NS_ASSERT(currentSublow == 0);
            NS_LOG_WARN("Close() -> CurrentSubflow: " << (int)currentSublow);
        } //-------------------------------
        return Close(currentSublow);
    }
    else
    { // CloseMultipathConnection(); this could be used as well...
        NS_LOG_INFO("Close has issued for listening socket, "
                    << this << ", it's endpoints ->  local/remote ("
                    << m_endPoint->GetLocalAddress() << ":" << m_endPoint->GetLocalPort() << "/"
                    << m_endPoint->GetPeerAddress() << ":" << m_endPoint->GetPeerPort()
                    << ") m_state: " << TcpStateName[m_state] << " -> CLOSED");
        NS_ASSERT(subflows.size() == 0);
        m_state = CLOSED;
        NotifyNormalClose();
        m_endPoint->SetDestroyCallback(MakeNullCallback<void>());
        m_tcp->DeAllocate(m_endPoint);
        m_endPoint = 0;
        // m_tcp->RemoveLocalToken(localToken);
        m_tcp->RemoveSocket(this);
        CancelAllSubflowTimers();
    }
    return true;
}

int
MpTcpSocketBase::Close(uint8_t sFlowIdx)
{
    NS_LOG_FUNCTION(this << (int)sFlowIdx);
    Ptr<MpTcpSubFlow> sFlow = subflows[sFlowIdx];

    // First we check to see if there is any unread rx data. Bug number 426 claims we should send
    // reset in this case.
    if (unOrdered.size() > 0 && FindPacketFromUnOrdered(sFlowIdx) &&
        !sFlow->Finished()) /* && recvingBuffer->PendingData() != 0 */
    {                       // I don't expect this to happens in normal scenarios!
        NS_ASSERT(server);
        // NS_FATAL_ERROR("Receiver called close() when there are some unread packets in its
        // buffer"); SendRST(sFlowIdx); //? CloseAndNotify(sFlowIdx);
        NS_LOG_UNCOND("unOrderedBuffer: " << unOrdered.size()
                                          << " currentSubflow: " << sFlow->routeId);
        CancelAllSubflowTimers(); // Danger?!?!
        return 0;
    }
    if (sendingBuffer.PendingData() > 0) // if (m_txBuffer.SizeFromSequence(m_nextTxSequence) > 0)
    { // App close with pending data must wait until all data transmitted from socket buffer
        NS_ASSERT(client);
        if (m_closeOnEmpty == false)
        {
            m_closeOnEmpty = true;
            if (flowType.compare("Large") == 0)
            { // This is only true for background flows
                cout << "[" << m_node->GetId() << "]{" << flowId << "}(" << flowType
                     << ") -> DoGenerateOutPutFile()" << endl;
                flowCompletionTime = false;
                //              DoGenerateOutPutFile();
                //              GeneratePlots();
            }
            NS_LOG_INFO("Socket " << this << " deferring close, Connection state "
                                  << TcpStateName[m_state]
                                  << " PendingData: " << sendingBuffer.PendingData());
        }
        return 0;
    }
    if (client)
        NS_ASSERT(sendingBuffer.Empty());
    if (server && !sFlow->Finished())
    {
        return 0;
    }
    if (server)
        NS_ASSERT_MSG(sFlow->Finished(),
                      " state: " << TcpStateName[sFlow->state] << " GotFin: " << sFlow->m_gotFin
                                 << " FinSeq: " << sFlow->m_finSeq
                                 << " mapDSN: " << sFlow->mapDSN.size());

    return DoClose(sFlowIdx);
}

/** Do the action to close the socket. Usually send a packet with appropriate
 flags depended on the current m_state. */
int
MpTcpSocketBase::DoClose(uint8_t sFlowIdx)
{
    NS_LOG_FUNCTION(this << (int)sFlowIdx << subflows.size());

    Ptr<MpTcpSubFlow> sFlow = subflows[sFlowIdx];
    // NS_LOG_INFO("DoClose -> Socket src/des (" << sFlow->sAddr << ":" << sFlow->sPort << "/" <<
    // sFlow->dAddr << ":" << sFlow->dPort << ")" << " state: " << TcpStateName[sFlow->state]);
    switch (sFlow->state)
    {
    case SYN_RCVD:
    case ESTABLISHED:
        // send FIN to close the peer
        SendEmptyPacket(sFlowIdx, TcpHeader::FIN);
        NS_LOG_INFO("(" << (int)sFlow->routeId
                        << ") ESTABLISHED -> FIN_WAIT_1 {DoClose} FIN is sent as separate pkt");
        sFlow->state = FIN_WAIT_1;
        break;
    case CLOSE_WAIT:
        // send FIN+ACK to close the peer (in normal scenario receiver should use this when she got
        // FIN from sender)
        SendEmptyPacket(sFlowIdx, TcpHeader::FIN | TcpHeader::ACK);
        NS_LOG_INFO("(" << (int)sFlow->routeId << ") CLOSE_WAIT -> LAST_ACK {DoClose}");
        sFlow->state = LAST_ACK;
        break;
    case SYN_SENT:
    case CLOSING:
        // Send RST if application closes in SYN_SENT and CLOSING
        NS_LOG_UNCOND(Simulator::Now().GetSeconds()
                      << " [" << m_node->GetId()
                      << "] DoClose (SYN_SENT or CLOSING)-> Socket src/des (" << sFlow->sAddr << ":"
                      << sFlow->sPort << "/" << sFlow->dAddr << ":" << sFlow->dPort << ")"
                      << " sFlow->state: " << TcpStateName[sFlow->state]);
        // CancelAllSubflowTimers(); // Danger?!?!
        // sFlow->state = CLOSED;
        cout << Simulator::Now().GetSeconds() << " [" << m_node->GetId() << "](" << (int)sFlowIdx
             << "){" << flowId << "}(" << flowType << ") " << TcpStateName[sFlow->state]
             << " <-- SendRST(DoCLOSE)" << endl;
        SendRST(sFlowIdx);
        CloseAndNotifyAllSubflows();
        break;
    case LISTEN:
    case LAST_ACK:
        // In these three states, move to CLOSED and tear down the end point
        CloseAndNotify(sFlowIdx);
        break;
    case CLOSED:
    case FIN_WAIT_1:
    case FIN_WAIT_2:
    case TIME_WAIT:
    default: /* mute compiler */
             // NS_LOG_INFO("DoClose -> DoNotting since subflow's state is " <<
        // TcpStateName[sFlow->state] << "(" << sFlow->routeId<< ")");
        //  Do nothing in these four states
        break;
    }
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
MpTcpSocketBase::SendRST(uint8_t sFlowIdx)
{
    NS_LOG_FUNCTION(this << (int)sFlowIdx); //
    // cout << Simulator::Now().GetSeconds() << " [" << m_node->GetId() << "]{"<< flowId <<"}
    // SendRST -> " << this << " ("<< (int) sFlowIdx << ")"<< endl;
    SendEmptyPacket(sFlowIdx, TcpHeader::RST);
    NotifyErrorClose();
    DeallocateEndPoint(sFlowIdx);
}

int
MpTcpSocketBase::SendDataPacket(uint8_t sFlowIdx, uint32_t size, bool withAck)
{
    NS_LOG_FUNCTION(this << (uint32_t)sFlowIdx << size << withAck);
    Ptr<MpTcpSubFlow> sFlow = subflows[sFlowIdx];
    Ptr<Packet> p = 0;
    DSNMapping* ptrDSN = 0;
    uint32_t packetSize = size;
    bool guard = false;
    /*
     * If timeout happens then TxSeqNumber would be shifted down to the seqNb after highestAck,
     * Note that 'maxSeqNb' would be still related to maxSeqNb ever sent.
     * here we can conclude that when maxSeqNb is bigger than TxSeqNumber -1, timeout has happened!
     * So next packet to send should be from subflowBuffer (mapDSN) instead of connection buffer
     * (sendingBuffer), In other situations 'maxSeqNb' should be equal to TxSeqNumber -1. Boolean
     * 'guard' is true only if packet going out is from subflow buffer!
     */
    if (sFlow->maxSeqNb > sFlow->TxSeqNumber - 1)
    {
        uint32_t IterNumber = 0;
        for (list<DSNMapping*>::iterator it = sFlow->mapDSN.begin();
             (it != sFlow->mapDSN.end() && guard == false);
             ++it)
        { // Look for match a segment from subflow's buffer where it is matched with TxSeqNumber
            IterNumber++;
            DSNMapping* ptr = *it;
            if (ptr->subflowSeqNumber == sFlow->TxSeqNumber)
            {
                ptrDSN = ptr;
                // p = Create<Packet>(ptrDSN->packet, ptrDSN->dataLevelLength);
                p = Create<Packet>(ptrDSN->dataLevelLength);
                packetSize = ptrDSN->dataLevelLength;
                guard = true;
                NS_LOG_LOGIC(Simulator::Now().GetSeconds()
                             << " A segment matched from subflow buffer. Its size is " << packetSize
                             << " IterNumInMapDSN: " << IterNumber << " maxSeqNb: "
                             << sFlow->maxSeqNb << " TxSeqNb: " << sFlow->TxSeqNumber
                             << " FastRecovery: " << sFlow->m_inFastRec
                             << " SegNb: " << ptrDSN->subflowSeqNumber); //
                break;
            }
        }
        if (p == 0)
        {
            NS_LOG_UNCOND("*** MaxSeq: " << sFlow->maxSeqNb
                                         << " sFlow->TxSeq: " << sFlow->TxSeqNumber);
            NS_ASSERT_MSG(p != 0,
                          "Subflow is in timeout recovery but there is no match segment in mapDSN "
                          "- Return -1 ?");
            return -1;
        }
    }
    else
    {
        NS_ASSERT_MSG(sFlow->maxSeqNb == sFlow->TxSeqNumber - 1,
                      " maxSN: " << sFlow->maxSeqNb << " TxSeqNb-1" << sFlow->TxSeqNumber - 1);
    }
    // If no packet has made yet and maxSeqNb is equal to TxSeqNumber -1, then we can safely create
    // a packet from connection buffer (sendingBuffer).
    if (p == 0 && ptrDSN == 0)
    {
        NS_ASSERT(!guard);
        NS_ASSERT(sFlow->maxSeqNb == sFlow->TxSeqNumber - 1);
        p = sendingBuffer.CreatePacket(size);
        if (p == 0)
        { // TODO I guess we should not return from here - What do we do then kill ourself?
            NS_LOG_WARN("[" << m_node->GetId() << "] (" << sFlow->routeId
                            << ") No data is available in SendingBuffer to create a pkt from it! "
                               "SendingBufferSize: "
                            << sendingBuffer.PendingData());
            NS_ASSERT_MSG(p != 0, "No data is available in SendingBuffer to create a pkt from it!");
            return 0;
        }
    }
    // TODO this Assertion will normaly fail because packet size is not set
    NS_ASSERT(packetSize <= size);
    NS_ASSERT(packetSize == p->GetSize());

    // This is data packet, so its TCP_Flag should be 0
    uint8_t flags = withAck ? TcpHeader::ACK : 0;

    // Add MPTCP header to the packet
    TcpHeader header;
    header.SetFlags(flags);
    header.SetSequenceNumber(SequenceNumber32(sFlow->TxSeqNumber));
    header.SetAckNumber(SequenceNumber32(sFlow->RxSeqNumber));
    header.SetSourcePort(sFlow->sPort);
    header.SetDestinationPort(sFlow->dPort);
    header.SetWindowSize(AdvertisedWindowSize());
    if (!guard)
    { // If packet is made from sendingBuffer, then we got to add the packet and its info to
      // subflow's mapDSN.
        sFlow->AddDSNMapping(sFlowIdx,
                             nextTxSequence,
                             packetSize,
                             sFlow->TxSeqNumber,
                             sFlow->RxSeqNumber /*, p->Copy()*/);
    }
    if (!guard)
    { // if packet is made from sendingBuffer, then we use nextTxSequence to OptDSN
        header.AppendOption(CreateObject<MpTcpOptionDataSeqMapping>(nextTxSequence, packetSize,sFlow->TxSeqNumber));
    }
    else
    { // if packet is made from subflow's Buffer (already sent packets), that packet's dataSeqNumber
      // should be added here!
        header.AppendOption(CreateObject<MpTcpOptionDataSeqMapping>(ptrDSN->dataSeqNumber, (uint16_t)packetSize, sFlow->TxSeqNumber));
        NS_ASSERT(packetSize == ptrDSN->dataLevelLength);
    }
    NS_LOG_ERROR("hLen: " << (int)hlen << " oLen: " << (int)olen << " pLen: " << (int)plen);

    // Check RTO, if expired then reschedule it again.
    SetReTxTimeout(sFlowIdx);
    NS_LOG_LOGIC ("Send packet via TcpL4Protocol with flags 0x" << std::hex << static_cast<uint32_t> (flags) << std::dec);

}

void
MpTcpSocketBase::ForwardUp(Ptr<Packet> p,
                           Ipv4Header header,
                           uint16_t port,
                           Ptr<Ipv4Interface> interface)
{
    NS_LOG_FUNCTION_NOARGS();
    DoForwardUp(p, header, port, interface);
}

void
MpTcpSocketBase::DoForwardUp(Ptr<Packet> p, Ipv4Header header, uint16_t port, Ptr<Ipv4Interface>)
{
    if (m_endPoint == 0)
    {
        NS_LOG_UNCOND("No endpoint exist");
        return;
    }
    NS_LOG_FUNCTION(this << " SubflowSize[" << subflows.size() << "]");
    Address fromAddress = InetSocketAddress(header.GetSource(), port);
    Address toAddress = InetSocketAddress(header.GetDestination(), m_endPoint->GetLocalPort());
    TcpHeader mptcpHeader;
    uint32_t bytesRemoved = packet->PeekHeader(mptcpHeader);
    m_remotePort = port;
    m_localPort = mptcpHeader.GetDestinationPort();

    /*
      if (!IsValidTcpSegment(tcpHeader.GetSequenceNumber(),
                             bytesRemoved,
                             packet->GetSize() - bytesRemoved))
      {
          return;
      }
    */
    if (subflows.size() == 0 && m_state == LISTEN)
    {
        NS_ASSERT(server && m_state == LISTEN);
        NS_LOG_UNCOND("Listening socket receives SYN packet, it need to be CLONED... "
                      << mptcpHeader);
        // Update the flow control window
        remoteRecvWnd = (uint32_t)mptcpHeader.GetWindowSize();
        // We need to define another ReadOption with no subflow in it
        if (ReadOptions(p, mptcpHeader) == false)
            return;
        // We need to define another ProcessListen with no subflow in it
        NS_ASSERT(m_endPoint->GetLocalPort() == mptcpHeader.GetDestinationPort());
        ProcessListen(p, mptcpHeader, fromAddress, toAddress);
        // Reset all variables after cloning is ended to ready for next connection
        mpRecvState = MP_NONE;
        mpEnabled = false;
        remoteToken = 0;
        localToken = 0;
        remoteRecvWnd = 1;
        return;
    }

    int sFlowIdx = LookupSubflow(m_localAddress, m_localPort, m_remoteAddress, m_remotePort);
    if (client && sFlowIdx > maxSubflows)
        exit(20);
    NS_ASSERT_MSG(sFlowIdx <= maxSubflows,
                  "Subflow number should be smaller than MaxNumOfSubflows");
    NS_ASSERT_MSG(sFlowIdx >= 0,
                  "sFlowIdx is -1, i.e., invalid packet received - This is not a bug we need to "
                  "deal with it - sFlowIdx: "
                      << sFlowIdx);

    Ptr<MpTcpSubFlow> sFlow = subflows[sFlowIdx];

    // uint32_t dataLen;   // packet's payload length
    // CWND
    remoteRecvWnd = (uint32_t)mptcpHeader.GetWindowSize(); // update the flow control window

    if (mptcpHeader.GetFlags() & TcpHeader::ACK)
    { // This function update subflow's lastMeasureRtt variable.
        EstimateRtt(sFlowIdx, mptcpHeader);
    }

    if (ReadOptions(sFlowIdx, p, mptcpHeader) == false)
        return;
    // TCP state machine code in different process functions
    // C.f.: tcp_rcv_state_process() in tcp_input.c in Linux kernel
    currentSublow = sFlow->routeId;
    switch (sFlow->state)
    {
    case ESTABLISHED:
        ProcessEstablished(sFlowIdx, p, mptcpHeader);
        break;
    case LISTEN:
        ProcessListen(sFlowIdx, p, mptcpHeader, fromAddress, toAddress);
        break;
    case TIME_WAIT:
        // Do nothing
        break;
    case CLOSED:
        NS_LOG_INFO(" (" << sFlow->routeId << ") " << TcpStateName[sFlow->state] << " -> Send RST");
        // Send RST if the incoming packet is not a RST
        if ((mptcpHeader.GetFlags() & ~(TcpHeader::PSH | TcpHeader::URG)) != TcpHeader::RST)
        { // Since sFlow->m_endPoint is not configured yet, we cannot use SendRST here
            cout << Simulator::Now().GetSeconds() << " [" << m_node->GetId() << "] ("
                 << (int)sFlowIdx << ") {" << flowId << "} SendRST(DoForwardup)" << endl;
            TcpHeader h;
            h.SetFlags(TcpHeader::RST);
            h.SetSequenceNumber(SequenceNumber32(sFlow->TxSeqNumber));
            h.SetAckNumber(SequenceNumber32(sFlow->RxSeqNumber));
            h.SetSourcePort(sFlow->sPort);
            h.SetDestinationPort(sFlow->dPort);
            h.SetWindowSize(AdvertisedWindowSize());
            m_tcp->SendPacket(Create<Packet>(),
                              h,
                              header.GetDestination(),
                              header.GetSource(),
                              FindOutputNetDevice(header.GetDestination()));
        }
        break;
    case SYN_SENT:
        ProcessSynSent(sFlowIdx, p, mptcpHeader);
        break;
    case SYN_RCVD:
        ProcessSynRcvd(sFlowIdx, p, mptcpHeader, fromAddress, toAddress);
        break;
    case FIN_WAIT_1:
    case FIN_WAIT_2:
    case CLOSE_WAIT:
        ProcessWait(sFlowIdx, p, mptcpHeader);
        break;
    case CLOSING:
        // ProcessClosing(sFlowIdx, p, mptcpHeader);
        break;
    case LAST_ACK:
        ProcessLastAck(sFlowIdx, p, mptcpHeader);
        break;
    default:
        // mute compiler
        break;
    }
}

bool
MpTcpSocketBase::SendPendingData(uint8_t sFlowIdx)
{

    NS_LOG_FUNCTION(this);
  // This condition only valid when sendingBuffer is empty!
  if (sendingBuffer.Empty() && sFlowIdx < maxSubflows)
    {
      uint32_t whileCounter = 0;
      Ptr<MpTcpSubFlow> sF = subflows[sFlowIdx];
      if (sF->mapDSN.size() > 0 && sF->maxSeqNb > sF->TxSeqNumber - 1)
        { // SendingBuffer is empty but subflowBuffer (mapDSN) is not. Also subflow is recovering from timeOut.
          uint32_t window = std::min(AvailableWindow(sFlowIdx), sF->MSS);
          // Send all data packets in subflowBuffer (mapDSN) until subflow's available window is full.
          while (window != 0 && window >= sF->MSS && sF->maxSeqNb > sF->TxSeqNumber - 1 && sF->mapDSN.size() > 0)
            { // In case case more than one packet can be sent, if subflow's window allow
              whileCounter++;
              NS_LOG_UNCOND("["<< m_node->GetId() <<"] MainBuffer is empty - subflowBuffer(" << sF->mapDSN.size()<< ") sFlow("<< (int)sFlowIdx << ") AvailableWindow: " << window << " CWND: " << sF->cwnd << " subflow is in timoutRecovery{" << (sF->mapDSN.size() > 0) << "} LoopIter: " << whileCounter);
              int ret = SendDataPacket(sF->routeId, window, false);
              if (ret < 0)
                {
                  NS_LOG_UNCOND(this <<" [" << m_node->GetId() << "]("<< sF->routeId << ")" << " SendDataPacket return -1 -> Return false from SendPendingData()!?");
                  return false; // Return -1 from SendDataPacket means segment match has not find from subflow buffer, so this loop should be stopped and return!!
                }
              NS_ASSERT(ret == 0);
              window = std::min(AvailableWindow(sFlowIdx), sF->MSS);
            }
          return false;  // SendingBuffer is empty so no point to continue further on this function
        }
      else
        { // SendingBuffer & subflowBuffer are empty i.e, nothing to re-send and nothing to send!!
          NS_LOG_LOGIC(Simulator::Now().GetSeconds()<< " [" << m_node->GetId() << "]" << " SendPendingData -> SubflowBuffer and main buffer is empty -> Return!");
          return false; // SendingBuffer is empty so no point to continue further on this function
        }
    }
    //  No endPoint -> Can't send any data
    if (m_endPoint == 0)
    {
        NS_LOG_ERROR("[" << m_node->GetId() << "] MpTcpSocketBase::SendPendingData:-> No endpoint");
        NS_ASSERT_MSG(m_endPoint != 0, " No endpoint");
        return false; // Is this the right way to handle this condition?
    }
    uint32_t nOctetsSent = 0;
    Ptr<MpTcpSubFlow> sFlow;

    // Send data as much as possible (it depends on subflows AvailableWindow and data in sending
    // buffer)

    // SCHED
    while (!sendingBuffer.Empty())
    {
        uint32_t window = 0;
        // Search for a subflow with available windows
        for (uint32_t i = 0; i < subflows.size(); i++)
        {
            if (subflows[lastUsedsFlowIdx]->state != ESTABLISHED)
                continue;
            window = std::min(AvailableWindow(lastUsedsFlowIdx),
                              sendingBuffer.PendingData()); // Get available window size
            if (window == 0)
            { // No more available window in the current subflow, try with another one
                NS_LOG_LOGIC("SendPendingData -> No window available on (" << (int)lastUsedsFlowIdx
                                                                           << ") Try next one!");
                lastUsedsFlowIdx = getSubflowToUse();
            }
            else
            {
                NS_LOG_LOGIC("SendPendingData -> Find subflow with spare window PendingData ("
                             << sendingBuffer.PendingData() << ") Available window ("
                             << AvailableWindow(lastUsedsFlowIdx) << ")");
                break;
            }
        }

        if (window == 0)
            break;

        // Take a pointer to the subflow with available window.
        sFlow = subflows[lastUsedsFlowIdx];

        // By this condition only connection initiator can send data need to be change though!
        // TODO IMPORTANT TO CHANGE THAT
        if (sFlow->state == ESTABLISHED)
        {
            currentSublow = sFlow->routeId;
            uint32_t s = std::min(window, sFlow->MSS); // Send no more than window
            if (sFlow->maxSeqNb > sFlow->TxSeqNumber - 1 &&
                sendingBuffer.PendingData() <= sFlow->MSS)
            { // When subflow is in timeout recovery and the last segment is not reached yet then
              // segment size should be equal to MSS
                s = sFlow->MSS;
            }
            int amountSent = SendDataPacket(sFlow->routeId, s, false);
            if (amountSent < 0)
            {
                NS_LOG_UNCOND(
                    this << " [" << m_node->GetId() << "](" << sFlow->routeId << ")"
                         << " SendDataPacket return -1 -> Return false from SendPendingData()!?");
                return false;
            }
            else
                nOctetsSent += amountSent; // Count total bytes sent in this loop
        } // end of if statement
        lastUsedsFlowIdx = getSubflowToUse();
    } // end of main while loop
    // NS_LOG_UNCOND ("["<< m_node->GetId() << "] SendPendingData -> amount data sent = " <<
    // nOctetsSent << "... Notify application.");

    if (nOctetsSent > 0)
        NotifyDataSent(GetTxAvailable());
    return (nOctetsSent > 0);
}

uint32_t
MpTcpSocketBase::AvailableWindow(uint8_t sFlowIdx)
{
    NS_LOG_FUNCTION(this << (int)sFlowIdx);

    Ptr<MpTcpSubFlow> sFlow = subflows[sFlowIdx];
    uint32_t window = std::min(remoteRecvWnd, sFlow->cwnd.Get());
    uint32_t unAcked = (sFlow->TxSeqNumber - (sFlow->highestAck + 1));
    uint32_t freeCWND = (window < unAcked) ? 0 : (window - unAcked);
    if (freeCWND < sFlow->MSS && sendingBuffer.PendingData() >= sFlow->MSS)
    {
        NS_LOG_WARN("AvailableWindow: (" << (int)sFlowIdx << ") -> " << freeCWND << " => 0"
                                         << " MSS: " << sFlow->MSS);
        return 0;
    }
    else
    {
        NS_LOG_WARN("AvailableWindow: (" << (int)sFlowIdx << ") -> " << freeCWND);
        return freeCWND;
    }
}

void
MpTcpSocketBase::SendEmptyPacket(uint8_t sFlowIdx, uint8_t flags)
{
    NS_LOG_FUNCTION(this << (int)sFlowIdx);
    Ptr<MpTcpSubFlow> sFlow = subflows[sFlowIdx];
    Ptr<Packet> p = Create<Packet>();

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
        // header.AddOptMPC(OPT_MPC, localToken);
        header.AppendOption(CreateObject<MpTcpOptionMultiPathCabable>(
            localToken)); // Adding MP_CAPABLE & Token to TCP option (5 Bytes)
        m_tcp->m_TokenMap[localToken] = m_endPoint;
        // m_tcp->m_TokenMap.insert(std::make_pair(localToken, m_endPoint))
        NS_LOG_UNCOND("[" << m_node->GetId() << "] (" << (int)sFlow->routeId
                          << ") SendEmptyPacket -> LOCALTOKEN is mapped to connection endpoint->"
                          << localToken << "->" << m_endPoint
                          << " TokenMapsSize : " << m_tcp->m_TokenMap.size());
    }
    else if ((sFlow->state == SYN_SENT && hasSyn &&
              sFlow->routeId ==
                  0) /* || (sFlow->state == SYN_RCVD && hasSyn && sFlow->routeId == 0)*/)
    { // no other subflow exists -> master subflow with tokenID 0
        // header.AddOptMPC(OPT_MPC, localToken);
        header.AppendOption(CreateObject<MpTcpOptionMultiPathCabable>(
            localToken)); // Adding MP_CAPABLE & Token to TCP option (4 Bytes for the token + 1 Byte
                          // for the flag)
    }
    else if (sFlow->state == SYN_SENT && hasSyn && sFlow->routeId != 0)
    {
        // header.AddOptJOIN(OPT_JOIN, remoteToken, 0); // addID should be zero?
        header.AppendOption(CreateObject<MpTcpOptionJoin>(remoteToken, 0));
        NS_LOG_INFO("why is it add id zero");
    }
    /*
    uint8_t plen = (4 - (olen % 4)) % 4;
    olen = (olen + plen) / 4;
    hlen = 5 + olen;
    header.SetLength(hlen);
    header.SetOptionsLength(olen);
    header.SetPaddingLength(plen);*/

    NS_LOG_INFO("sending packet from " << sFlow->sAddr << " to " << sFlow->dAddr);

    m_tcp->SendPacket(p, header, sFlow->sAddr, sFlow->dAddr, FindOutputNetDevice(sFlow->sAddr));
    // sFlow->rtt->SentSeq (sFlow->TxSeqNumber, 1);            // notify the RTT

    if (sFlow->retxEvent.IsExpired() && (hasFin || hasSyn) && !isAck)
    { // Retransmit SYN / SYN+ACK / FIN / FIN+ACK to guard against lost
        // RTO = sFlow->rtt->RetransmitTimeout();
        // sFlow->retxEvent =
        //    Simulator::Schedule(RTO, &MpTcpSocketBase::SendEmptyPacket, this, sFlowIdx, flags);
        sFlow->retxEvent =
            Simulator::Schedule(RTO, &MpTcpSocketBase::SendEmptyPacket, this, sFlowIdx, flags);
        if (hasSyn)
        {
            // cout << this << " ["<< m_node->GetId() << "]("<<(int)sFlowIdx <<") SendEmptyPacket ->
            // "<< TcpFlagPrinter(flags)<< " ReTxTimer set for SYN / SYN+ACK now " << Simulator::Now
            // ().GetSeconds () << " Expire at " << (Simulator::Now () + RTO).GetSeconds () << "
            // RTO: " << RTO.GetSeconds() << " FlowType: " << flowType << " Header: "<< header <<
            // endl;
            NS_LOG_UNCOND(
                this << " [" << m_node->GetId() << "](" << (int)sFlowIdx << ") SendEmptyPacket -> "
                     << TcpFlagPrinter(flags) << " ReTxTimer set for SYN / SYN+ACK now "
                     << Simulator::Now().GetSeconds() << " Expire at "
                     << (Simulator::Now() + RTO).GetSeconds() << " RTO: " << RTO.GetSeconds()
                     << " FlowType: " << flowType << " Header: " << header);
        }
        if (hasFin)
        {
            NS_LOG_UNCOND(
                this << " [" << m_node->GetId() << "](" << (int)sFlowIdx << ") SendEmptyPacket -> "
                     << TcpFlagPrinter(flags) << " ReTxTimer set for FIN / FIN+ACK now "
                     << Simulator::Now().GetSeconds() << " Expire at "
                     << (Simulator::Now() + RTO).GetSeconds() << " RTO: " << RTO.GetSeconds()
                     << " FlowType: " << flowType << " Header: " << header);
        }
    }

    // if (!isAck)
    NS_LOG_INFO("(" << (int)sFlowIdx << ") SendEmptyPacket-> " << header
                    << " Length: " << (int)header.GetLength());
}

int
MpTcpSocketBase::SetupCallback()
{
    NS_LOG_FUNCTION(this);
    if (m_endPoint == 0)
    {
        return -1;
    }
    // set the call backs method
    m_endPoint->SetRxCallback(
        MakeCallback(&MpTcpSocketBase::ForwardUp, Ptr<MpTcpSocketBase>(this)));
    m_endPoint->SetDestroyCallback(
        MakeCallback(&MpTcpSocketBase::Destroy, Ptr<MpTcpSocketBase>(this)));

    // Setup local add:port of this mptcp endpoint.
    m_localAddress = m_endPoint->GetLocalAddress();
    m_localPort = m_endPoint->GetLocalPort();

    return 0;
}

void
MpTcpSocketBase::AdvertiseAvailableAddresses()
{
    NS_LOG_FUNCTION(m_node->GetId());
    if (mpEnabled == true)
    {
        // There is at least one subflow
        Ptr<MpTcpSubFlow> sFlow = subflows[0];
        NS_ASSERT(sFlow != 0);

        // Change the MPTCP send state to MP_ADDR
        mpSendState = MP_ADDR;
        MpTcpAddressInfo* addrInfo;
        Ptr<Packet> pkt = Create<Packet>();

        TcpHeader header;

        header.SetFlags(TcpHeader::ACK);
        header.SetSequenceNumber(SequenceNumber32(sFlow->TxSeqNumber));
        header.SetAckNumber(SequenceNumber32(sFlow->RxSeqNumber));
        header.SetSourcePort(m_localPort);       // m_endPoint->GetLocalPort()
        header.SetDestinationPort(m_remotePort); // TODO Is this right?

        // Object from L3 to access to routing protocol, Interfaces and NetDevices and so on.
        Ptr<Ipv4L3Protocol> ipv4 = m_node->GetObject<Ipv4L3Protocol>();
        for (uint32_t i = 0; i < ipv4->GetNInterfaces(); i++)
        {
            // Ptr<NetDevice> device = m_node->GetDevice(i);
            Ptr<Ipv4Interface> interface = ipv4->GetInterface(i);
            Ipv4InterfaceAddress interfaceAddr = interface->GetAddress(0);

            // Skip the loop-back
            if (interfaceAddr.GetLocal() == Ipv4Address::GetLoopback())
                continue;

            addrInfo = new MpTcpAddressInfo();
            addrInfo->addrID = i;
            addrInfo->ipv4Addr = interfaceAddr.GetLocal();
            addrInfo->mask = interfaceAddr.GetMask();
            header.AppendOption(
                CreateObject<MpTcpOptionAdress>(addrInfo->addrID, addrInfo->ipv4Addr));
            localAddrs.push_back(addrInfo);
            uint8_t plen = (4 - (olen % 4)) % 4;
            header.SetWindowSize(AdvertisedWindowSize());
            // m_tcp->SendPacket(pkt, header, m_endPoint->GetLocalAddress(), m_remoteAddress);
            m_tcp->SendPacket(pkt,
                              header,
                              m_localAddress,
                              m_remoteAddress,
                              FindOutputNetDevice(m_localAddress));
            NS_LOG_INFO("AdvertiseAvailableAddresses-> " << header);
        }
    }
    else
    {
        NS_FATAL_ERROR("Need to be Looked...");
    }
}

void
MpTcpSocketBase::CompleteFork(Ptr<Packet> p,
                              const TcpHeader& h,
                              const Address& fromAddress,
                              const Address& toAddress)
{
    NS_LOG_FUNCTION(this);
    // In closed object following conditions should be true!
    server = true;

    // Get port and address from peer (connecting host)
    if (InetSocketAddress::IsMatchingType(toAddress))
    {
        m_endPoint = m_tcp->Allocate(InetSocketAddress::ConvertFrom(toAddress).GetIpv4(),
                                     InetSocketAddress::ConvertFrom(toAddress).GetPort(),
                                     InetSocketAddress::ConvertFrom(fromAddress).GetIpv4(),
                                     InetSocketAddress::ConvertFrom(fromAddress).GetPort());
    }
    NS_ASSERT(InetSocketAddress::ConvertFrom(toAddress).GetIpv4() == m_localAddress);
    NS_ASSERT(InetSocketAddress::ConvertFrom(toAddress).GetPort() == m_localPort);
    NS_ASSERT(InetSocketAddress::ConvertFrom(fromAddress).GetIpv4() == m_remoteAddress);
    NS_ASSERT(InetSocketAddress::ConvertFrom(fromAddress).GetPort() == m_remotePort);

    // We only setup destroy callback for MPTCP connection's endPoints, not on subflows endpoints.
    SetupCallback();
    // m_tcp->m_sockets.push_back(this); // TMP REMOVE

    // Create new master subflow (master subsock) and assign its endpoint to the connection endpoint
    Ptr<MpTcpSubFlow> sFlow = CreateObject<MpTcpSubFlow>();
    sFlow->routeId = (subflows.size() == 0 ? 0 : subflows[subflows.size() - 1]->routeId + 1);
    sFlow->sAddr = m_localAddress; // m_endPoint->GetLocalAddress();
    sFlow->sPort = m_localPort;    // m_endPoint->GetLocalPort();
    sFlow->dAddr = m_remoteAddress;
    sFlow->dPort = m_remotePort; // TODO ? I guess m_remotePort would be used here!
    sFlow->MSS = segmentSize;
    sFlow->state = SYN_RCVD;
    sFlow->cnTimeout = m_cnTimeout;
    sFlow->cnRetries = m_cnRetries;
    sFlow->cnCount = sFlow->cnRetries;
    sFlow->m_endPoint =
        m_endPoint; // This is master subsock, its endpoint is the same as connection endpoint.
    NS_LOG_INFO("(" << (int)sFlow->routeId << ") LISTEN -> SYN_RCVD");
    subflows.insert(subflows.end(), sFlow);
    sFlow->RxSeqNumber = (mptcpHeader.GetSequenceNumber()).GetValue() +
                         1; // Set the subflow sequence number and send SYN+ACK
    NS_LOG_DEBUG("CompleteFork -> RxSeqNb: " << sFlow->RxSeqNumber
                                             << " highestAck: " << sFlow->highestAck);
    SendEmptyPacket(sFlow->routeId, TcpHeader::SYN | TcpHeader::ACK);

    // Update currentSubflow in case close just after 3WHS.
    currentSublow = sFlow->routeId;
    // NS_LOG_UNCOND("CompleteFork -> receivingBufferSize: " << recvingBuffer->bufMaxSize); //
    NS_LOG_INFO(this << "  MPTCP connection is initiated (Receiver): " << sFlow->sAddr << ":"
                     << sFlow->sPort << " -> " << sFlow->dAddr << ":" << sFlow->dPort);
}

bool
MpTcpSocketBase::InitiateSubflows()
{
    NS_LOG_FUNCTION_NOARGS(); //
    NS_LOG_DEBUG(
        "----------------------------- InitiateSubflows By Client ---------------------------");
    for (uint32_t i = 0; i < localAddrs.size(); i++)
        for (uint32_t j = i; j < remoteAddrs.size(); j++)
        {
            uint8_t addrID = localAddrs[i]->addrID;
            Ipv4Address local = localAddrs[i]->ipv4Addr;
            Ipv4Address remote = remoteAddrs[j]->ipv4Addr;

            // skip already established flows and if there is no route between a pair
            if (((local == m_localAddress) || (remote == m_remoteAddress)) ||
                (!IsThereRoute(local, remote)))
            {
                NS_LOG_INFO("InitiateSubflows -> Skip subflow which is already established or has "
                            "not a route ("
                            << local << " -> " << remote << ")");
                continue;
            }
            NS_LOG_LOGIC("IsThereRoute() -> Route from src " << local << " to dst " << remote
                                                             << ", exist !");

            // Create new subflow
            Ptr<MpTcpSubFlow> sFlow = CreateObject<MpTcpSubFlow>();
            sFlow->routeId =
                (subflows.size() == 0 ? 0 : subflows[subflows.size() - 1]->routeId + 1);

            // Set up subflow local addrs:port from its endpoint
            sFlow->sAddr = local;
            sFlow->sPort = m_endPoint->GetLocalPort();
            sFlow->dAddr = remote;
            sFlow->dPort = m_remotePort; // TODO Is this right?
            sFlow->MSS = segmentSize;
            // CWND
            sFlow->cwnd = sFlow->MSS; // We should do this ... since cwnd is 0
            sFlow->state = SYN_SENT;
            sFlow->cnTimeout = m_cnTimeout;
            sFlow->cnRetries = m_synRetries;
            sFlow->cnCount = sFlow->cnRetries;
            sFlow->m_endPoint = m_tcp->Allocate(sFlow->sAddr,
                                                sFlow->sPort,
                                                sFlow->dAddr,
                                                sFlow->dPort); // Insert New Subflow to the list
            if (sFlow->m_endPoint == 0)
                return -1;
            sFlow->m_endPoint->SetRxCallback(
                MakeCallback(&MpTcpSocketBase::ForwardUp, Ptr<MpTcpSocketBase>(this)));
            subflows.push_back(sFlow);

            // Create packet and add MP_JOIN option to it.
            Ptr<Packet> pkt = Create<Packet>();
            TcpHeader header;
            header.SetFlags(TcpHeader::SYN);
            header.SetSequenceNumber(SequenceNumber32(sFlow->TxSeqNumber));
            header.SetAckNumber(SequenceNumber32(sFlow->RxSeqNumber));
            header.SetSourcePort(sFlow->sPort);
            header.SetDestinationPort(sFlow->dPort);
            header.SetWindowSize(AdvertisedWindowSize());
            header.AppendOption(MpTcpOptionJoin(remoteToken, addrID));
            NS_LOG_ERROR("InitiateSubflow->Header: " << header);

            // Send packet lower down the networking stack
            m_tcp->SendPacket(pkt, header, local, remote, FindOutputNetDevice(local));
            NS_LOG_INFO("InitiateSubflows -> (" << local << " -> " << remote << ") | " << header);
        }
    return true;
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

Ptr<NetDevice>
MpTcpSocketBase::FindOutputNetDevice(Ipv4Address src)
{
    Ptr<Ipv4L3Protocol> ipv4 = m_node->GetObject<Ipv4L3Protocol>();
    uint32_t oInterface = ipv4->GetInterfaceForAddress(src);
    Ptr<NetDevice> oNetDevice = ipv4->GetNetDevice(oInterface);

    //  Ptr<Ipv4Interface> interface = ipv4->GetRealInterfaceForAddress(src);
    //  Ptr<NetDevice> netDevice = interface->GetDevice();
    //  NS_ASSERT(netDevice == oNetDevice);
    // NS_LOG_INFO("FindNetDevice -> Src: " << src << " NIC: " << netDevice->GetAddress());
    return oNetDevice;
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

void
MpTcpSocketBase::ProcessListen(Ptr<Packet> packet,
                               const TcpHeader& mptcpHeader,
                               const Address& fromAddress,
                               const Address& toAddress)
{
    NS_LOG_FUNCTION(this << mptcpHeader);

    // Extract the flags. PSH and URG are not honoured.
    uint8_t tcpflags = mptcpHeader.GetFlags() & ~(TcpHeader::PSH | TcpHeader::URG);

    // Fork a socket if received a SYN. Do nothing otherwise.
    // C.f.: the LISTEN part in tcp_v4_do_rcv() in tcp_ipv4.c in Linux kernel
    if (tcpflags != TcpHeader::SYN)
    {
        return;
    }

    // Call socket's notify function to let the server app know we got a SYN
    // If the server app refuses the connection, do nothing
    if (!NotifyConnectionRequest(fromAddress))
    {
        NS_LOG_ERROR("Server refuse the incoming connection!");
        return;
    }

    // Clone the socket, simulate Fork()
    // Ptr<MpTcpSocketBase> newSock = CopyObject<MpTcpSocketBase>(this);
    Ptr<MpTcpSocketBase> newSock = DynamicCast<MpTcpSocketBase>(Fork());
    // NS_LOG_UNCOND ("Clone new MpTcpSocketBase new connection. ListenerSocket " << this << "
    // AcceptedSocket "<< newSock);
    Simulator::ScheduleNow(&MpTcpSocketBase::CompleteFork,
                           newSock,
                           packet,
                           mptcpHeader,
                           fromAddress,
                           toAddress);
}

void
MpTcpSocketBase::ProcessEstablished(uint8_t sFlowIdx,
                                    Ptr<Packet> packet,
                                    const TcpHeader& mptcpHeader)
{
    NS_LOG_FUNCTION(this << mptcpHeader);

    // Extract the flags. PSH and URG are not honoured.
    uint8_t tcpflags = mptcpHeader.GetFlags() & ~(TcpHeader::PSH | TcpHeader::URG);

    // Different flags are different events
    if (tcpflags == TcpHeader::ACK)
    {
        ReceivedAck(sFlowIdx, packet, mptcpHeader);
    }
}

bool
MpTcpSocketBase::ReadOptions(uint8_t sFlowIdx, Ptr<Packet> pkt, const TcpHeader& mptcpHeader)
{
    NS_LOG_FUNCTION(this << (int)sFlowIdx << mptcpHeader);
    Ptr<MpTcpSubFlow> sFlow = subflows[sFlowIdx];
    uint8_t flags = mptcpHeader.GetFlags();
    bool hasSyn = flags & TcpHeader::SYN;
    bool TxAddr = false;

    if (mptcpHeader.HasOption(TcpOption::MP_MPC) && hasSyn && (mpRecvState == MP_NONE))
    {
        // SYN+ACK would be send later on by ProcessSynRcvd(...)
        mpRecvState = MP_MPC;
        mpEnabled = true;
        remoteToken =
            DynamicCast<const MpTcpOptionMultiPathCabable>(mptcpHeader.GetOption(TcpOption::MP_MPC))
                ->m_senderToken;

        NS_ASSERT(remoteToken != 0);
        NS_ASSERT(client);
    }
    if (mptcpHeader.HasOption(TcpOption::MP_JOIN) && hasSyn)
    {
        if ((mpSendState == MP_ADDR) &&
            (localToken ==
                 DynamicCast<const MpTcpOptionJoin>(mptcpHeader.GetOption(TcpOption::MP_JOIN))
                     ->m_senderToken;))
        { // SYN+ACK would be send later on by ProcessSynRcvd(...)
            // Join option is sent over the path (couple of addresses) not already in use
            NS_LOG_UNCOND("Server receive new subflow!");
        }
    }
    if (mptcpHeader.HasOption(TcpOption::MP_ADDR) && (mpRecvState == MP_MPC))
    {
        // Receiver store sender's addresses information and send back its addresses.
        // If there are several addresses to advertise then multiple OPT_ADDR would be attached to
        // the TCP Options.
        MpTcpAddressInfo* addrInfo = new MpTcpAddressInfo();
        const TcpHeader::TcpOptionList& optionlist = mptcpHeader.GetOptionList();
        for (auto i = optionlist.begin(); i != optionlist.end(); ++i)
        {
            if ((*i)->GetKind() == MP_ADDR)
            {
                MpTcpAddressInfo* addrInfo = new MpTcpAddressInfo();
                auto ad = DynamicCast<const MpTcpOptionAdress>((*i));
                addrInfo->addrID = ad->m_addrId;
                addrInfo->ipv4Addr = ad->m_addr;
                remoteAddrs.push_back(addrInfo);
                TxAddr = true;
            }
        }
    }
    if (mptcpHeader.HasOption(TcpOption::MP_DSN))
    {
        // TODO maybe something should happen here ...
        NS_LOG_LOGIC(this << " ReadOption-> OPT_DSN -> we'll deal with it later on");
    }
    if (hasSyn)
    {
        // incoming packet has syn but without proper mptcp option
        // for non mptcp communication -> not relevant for Thesis
        // TODO send a reset not implemented yet no one cares
    }
    if (TxAddr == true)
    {
        mpRecvState = MP_ADDR;
        // If addresses did not send yet then advertise them...
        if (mpSendState != MP_ADDR)
        {
            NS_LOG_DEBUG(Simulator::Now().GetSeconds()
                         << "---------------------- AdvertiseAvailableAddresses By Server "
                         << "---------------------");
            NS_ASSERT(pathManager == FullMesh);
            AdvertiseAvailableAddresses(); // this is what the receiver has to do
            return false;
        }
        // If addresses already sent then initiate subflows...
        else if (mpSendState == MP_ADDR)
        {
            NS_ASSERT(pathManager == FullMesh);
            InitiateSubflows(); // this is what the initiator has to do
            return false;
        }
    }
    return true;
}

bool
MpTcpSocketBase::ReadOptions(Ptr<Packet> pkt, const TcpHeader& mptcpHeader)
{ // Any packet without SYN and MP_CAPABLE is not being processed!
    NS_LOG_FUNCTION(this << mptcpHeader);
    NS_ASSERT(remoteToken == 0 && mpEnabled == false);

    uint8_t flags = mptcpHeader.GetFlags();
    bool hasSyn = flags & TcpHeader::SYN;

    if (mptcpHeader.HasOption(TcpOption::MP_MPC) && hasSyn && (mpRecvState == MP_NONE))
    {
        mpRecvState = MP_MPC;
        mpEnabled = true;
        remoteToken =
            DynamicCast<const MpTcpOptionMultiPathCabable>(mptcpHeader.GetOption(TcpOption::MP_MPC))
                ->m_senderToken;
        if (remoteToken == 0)
        {
            NS_ASSERT(remoteToken != 0);
        } // Correct condition
        return true;
    }
    NS_LOG_UNCOND("[" << m_node->GetId()
                      << "] Wrong option is received -> RETURN. MptcpHeader: " << mptcpHeader);
    return false; // If no option MP_CAPABLE is found -> RETURN then ForwardUp() should RETURN too!
}

void
MpTcpSocketBase::EstimateRtt(uint8_t sFlowIdx, const TcpHeader&)
{
    NS_LOG_FUNCTION(this << (int)sFlowIdx);
    Ptr<MpTcpSubFlow> sFlow = subflows[sFlowIdx];
    sFlow->lastMeasuredRtt = sFlow->rtt->AckSeq(mptcpHeader.GetAckNumber());
    // sFlow->measuredRTT.insert(sFlow->measuredRTT.end(),
    // sFlow->rtt->GetCurrentEstimate().GetSeconds());
}

void
MpTcpSocketBase::EstimateRtt(const TcpHeader&)
{
    NS_LOG_FUNCTION_NOARGS();
}

void
MpTcpSocketBase::ReceivedAck(uint8_t sFlowIdx, Ptr<Packet> packet, const TcpHeader& mptcpHeader)
{
    NS_LOG_FUNCTION(this << sFlowIdx << mptcpHeader);

    Ptr<MpTcpSubFlow> sFlow = subflows[sFlowIdx];
    uint32_t ack = (mptcpHeader.GetAckNumber()).GetValue();
    // Stop execution if TCPheader is not ACK at all.
    if (0 == (mptcpHeader.GetFlags() & TcpHeader::ACK))
    { // Ignore if no ACK flag
        NS_LOG_DEBUG("ReceivedAck:  no ACK in HEADER")
    }
    else if (ack <= sFlow->highestAck + 1)
    {
        NS_LOG_LOGIC("This acknowlegment" << mptcpHeader.GetAckNumber()
                                          << "do not ack the latest data in subflow level");
        list<DSNMapping*>::iterator current = sFlow->mapDSN.begin();
        list<DSNMapping*>::iterator next = sFlow->mapDSN.begin();
        while (current != sFlow->mapDSN.end())
        {
            ++next;
            DSNMapping* ptrDSN = *current;
            // All segments before ackSeqNum should be removed from the mapDSN list.
            if (ptrDSN->subflowSeqNumber + ptrDSN->dataLevelLength <= ack)
            { // Optional task ...
              // next = sFlow->mapDSN.erase(current);
              // delete ptrDSN;
            }
            // There is a sent segment with subflowSN equal to ack but the ack is smaller than
            // already receveid acked!
            else if ((ptrDSN->subflowSeqNumber == ack) && (ack < sFlow->highestAck + 1))
            { // Case 1: Old ACK, ignored.
                NS_LOG_WARN("Ignored ack of " << mptcpHeader.GetAckNumber());
                NS_ASSERT(3 != 3);
                break;
            }
            // There is a sent segment with requested SequenceNumber and ack is for first unacked
            // byte!!
            else if ((ptrDSN->subflowSeqNumber == ack) && (ack == sFlow->highestAck + 1))
            { // Case 2: Potentially a duplicated ACK, so ack should be smaller than nextExpectedSN
              // to send.
                if (ack < sFlow->TxSeqNumber)
                {
                    // NS_LOG_ERROR(Simulator::Now().GetSeconds()<< " [" << m_node->GetId()<< "]
                    // Duplicated ack received for SeqgNb: " << ack << " DUPACKs: " <<
                    // sFlow->m_dupAckCount + 1);
                    DupAck(sFlowIdx, ptrDSN);
                    break;
                }
                // otherwise, the ACK is precisely equal to the nextTxSequence
                NS_ASSERT(ack <= sFlow->TxSeqNumber);
                break;
            }
            current = next;
        }
    }
    else if (ack > sFlow->highestAck + 1)
    { // Case 3: New ACK, reset m_dupAckCount and update m_txBuffer (DSNMapping List)
        NS_LOG_WARN("New ack of " << mptcpHeader.GetAckNumber());
        // CWND
        NewAckNewReno(sFlowIdx, mptcpHeader, 0);
        sFlow->m_dupAckCount = 0;
    }
    // If there is any data piggy-backed, store it into m_rxBuffer
    if (packet->GetSize() > 0)
    {
        NS_LOG_WARN(this << " ReceivedAck -> There is data piggybacked, deal with it...");
        ReceivedData(sFlowIdx, packet, mptcpHeader);
    }
    // Find last data acked ... for generating output file!
    if (!server)
        IsLastAck();
}

void
MpTcpSocketBase::DupAck(const TcpHeader& t, uint32_t count)
{
    NS_LOG_FUNCTION_NOARGS();
}

void
MpTcpSocketBase::DupAck(uint8_t sFlowIdx, DSNMapping* ptrDSN)
{
    // CWND

    Ptr<MpTcpSubFlow> sFlow = subflows[sFlowIdx];
    sFlow->m_dupAckCount++;
    ptrDSN->dupAckCount++; // Used for evaluation purposes only
    uint32_t segmentSize = sFlow->MSS;
    // calculateTotalCWND();

    // Congestion control algorithms
    if (sFlow->m_dupAckCount == 3 && !sFlow->m_inFastRec)
    { // FastRetrasmsion
        NS_LOG_WARN(Simulator::Now().GetSeconds()
                    << " DupAck -> Subflow (" << (int)sFlowIdx
                    << ") 3rd duplicated ACK for segment (" << ptrDSN->subflowSeqNumber << ")");

        // Cut the window to the half
        ReduceCWND(sFlowIdx, ptrDSN);
        FastReTxs++;
    }
    else if (sFlow->m_inFastRec)
    { // Fast Recovery
        // Increase cwnd for every additional DupACK (RFC2582, sec.3 bullet #3)
        sFlow->cwnd += segmentSize;
        NS_LOG_WARN("DupAck-> FastRecovery. Increase cwnd by one MSS, from "
                    << sFlow->cwnd.Get() << " -> " << sFlow->cwnd
                    << " AvailableWindow: " << AvailableWindow(sFlowIdx));
        FastRecoveries++;
        // Send more data into pipe if possible to get ACK clock going
        // SCHED
        SendPendingData(sFlow->routeId); // dupack()
    }
    else
    {
        NS_LOG_WARN("Limited transmit is not enabled... DupAcks: " << ptrDSN->dupAckCount);
    }
    //  else if (!sFlow->m_inFastRec && sFlow->m_limitedTx && sendingBuffer->PendingData() > 0)
    //    { // RFC3042 Limited transmit: Send a new packet for each duplicated ACK before fast
    //    retransmit
    //      NS_LOG_INFO ("Limited transmit");
    //      uint32_t sz = SendDataPacket(sFlowIdx, sFlow->MSS, false); // WithAck or Without ACK?
    //      NotifyDataSent(sz);
    //    };
}

void
MpTcpSocketBase::DoRetransmit(uint8_t sFlowIdx, DSNMapping* ptrDSN)
{
    NS_LOG_FUNCTION(this);
    Ptr<MpTcpSubFlow> sFlow = subflows[sFlowIdx];

    // This retransmit segment should be the lost segment.
    NS_ASSERT(ptrDSN->subflowSeqNumber >= sFlow->highestAck + 1);

    SetReTxTimeout(sFlowIdx); // reset RTO

    // we retransmit only one lost pkt
    // Ptr<Packet> pkt = Create<Packet>(ptrDSN->packet, ptrDSN->dataLevelLength);
    Ptr<Packet> pkt = Create<Packet>(ptrDSN->dataLevelLength);
    if (pkt == 0)
        NS_ASSERT(3 != 3);

    TcpHeader header;
    header.SetSourcePort(sFlow->sPort);
    header.SetDestinationPort(sFlow->dPort);
    header.SetFlags(TcpHeader::NONE); // Change to NONE Flag
    header.SetSequenceNumber(SequenceNumber32(ptrDSN->subflowSeqNumber));
    header.SetAckNumber(SequenceNumber32(sFlow->RxSeqNumber));
    header.SetWindowSize(AdvertisedWindowSize());
    // Make sure info here comes from ptrDSN...
    header.AppendOption(Create<MpTcpOptionDataSeqMapping>(ptrDSN->dataSeqNumber,
                                                          ptrDSN->dataLevelLength,
                                                          ptrDSN->subflowSeqNumber));

    NS_LOG_WARN(Simulator::Now().GetSeconds()
                << " RetransmitSegment -> " << " localToken " << localToken << " Subflow "
                << (int)sFlowIdx << " DataSeq " << ptrDSN->dataSeqNumber << " SubflowSeq "
                << ptrDSN->subflowSeqNumber << " dataLength " << ptrDSN->dataLevelLength
                << " packet size " << pkt->GetSize() << " 3DupACK");

    // Send Segment to lower layer
    m_tcp->SendPacket(pkt, header, sFlow->sAddr, sFlow->dAddr, FindOutputNetDevice(sFlow->sAddr));

    // TxBytes += ptrDSN->dataLevelLength + 62;

    // Notify RTT
    sFlow->rtt->SentSeq(SequenceNumber32(ptrDSN->subflowSeqNumber), ptrDSN->dataLevelLength);

    // In case of RTO, advance m_nextTxSequence
    sFlow->TxSeqNumber =
        std::max(sFlow->TxSeqNumber, ptrDSN->subflowSeqNumber + ptrDSN->dataLevelLength);

    // highest sent sequence number should be updated!
    sFlow->maxSeqNb = std::max(sFlow->maxSeqNb, sFlow->TxSeqNumber - 1);

    NS_LOG_INFO("(" << (int)sFlowIdx << ") DoRetransmit -> " << header);
}

uint16_t
MpTcpSocketBase::AdvertisedWindowSize()
{
    return (uint16_t)65535;
}

void
MpTcpSocketBase::SetReTxTimeout(uint8_t sFlowIdx)
{
    Ptr<MpTcpSubFlow> sFlow = subflows[sFlowIdx];
    if (sFlow->retxEvent.IsExpired())
    {
        Time rto = sFlow->rtt->RetransmitTimeout();
        sFlow->retxEvent = Simulator::Schedule(rto, &MpTcpSocketBase::ReTxTimeout, this, sFlowIdx);
    }
}

bool
MpTcpSocketBase::FindPacketFromUnOrdered(uint8_t sFlowIdx)
{
    NS_LOG_FUNCTION((int)sFlowIdx);
    bool reValue = false;
    list<DSNMapping*>::iterator current = unOrdered.begin();
    while (current != unOrdered.end())
    {
        DSNMapping* ptrDSN = *current;
        if (ptrDSN->subflowIndex == sFlowIdx)
        {
            reValue = true;
            NS_LOG_LOGIC("(" << (int)sFlowIdx << ") FindPacketFromUnOrdered -> SeqNb"
                             << ptrDSN->subflowSeqNumber << " pSize: " << ptrDSN->dataLevelLength);
            break;
        }
        current++;
    }
    return reValue;
}

void
MpTcpSocketBase::ReduceCWND(uint8_t sFlowIdx, DSNMapping* ptrDSN)
{
    // CWND gets called
    Ptr<MpTcpSubFlow> sFlow = subflows[sFlowIdx];
    uint32_t mss = sFlow->MSS;
    int d = 0;
    calculateTotalCWND();

    switch (AlgoCC)
    {
    case Uncoupled_TCPs:
    case Linked_Increases:
    case RTT_Compensator:
    case COUPLED_INC:
    case COUPLED_EPSILON:
    case UNCOUPLED:
        sFlow->ssthresh = std::max(2 * mss, BytesInFlight(sFlowIdx) / 2);
        sFlow->cwnd = sFlow->ssthresh + 3 * mss;
        break;

    case COUPLED_SCALABLE_TCP:
        d = (int)sFlow->cwnd.Get() - (compute_total_window() >> 3);
        if (d < 0)
            d = 0;
        sFlow->ssthresh = max(2 * mss, (uint32_t)d);
        sFlow->cwnd = sFlow->ssthresh + 3 * mss;
        break;

    case COUPLED_FULLY:
        d = (int)sFlow->cwnd.Get() - compute_total_window() / B;
        if (d < 0)
            d = 0;
        sFlow->ssthresh = max(2 * mss, (uint32_t)d);
        sFlow->cwnd = sFlow->ssthresh + 3 * mss;
        break;

    case Fully_Coupled:
        d = sFlow->cwnd.Get() - totalCwnd / 2;
        if (d < 0)
            d = 0;
        sFlow->ssthresh = std::max(2 * mss, (uint32_t)d);
        sFlow->cwnd = sFlow->ssthresh + 3 * mss;
        break;

    default:
        NS_ASSERT(3 != 3);
        break;
    }
    // update
    sFlow->m_recover = SequenceNumber32(sFlow->maxSeqNb + 1);
    sFlow->m_inFastRec = true;

    // Retrasnmit a specific packet (lost segment)
    DoRetransmit(sFlowIdx, ptrDSN);
}

void
MpTcpSocketBase::calculateTotalCWND()
{
    totalCwnd = 0;
    for (uint32_t i = 0; i < subflows.size(); i++)
    {
        if (subflows[i]->m_inFastRec)
            totalCwnd += subflows[i]->ssthresh;
        else
            totalCwnd += subflows[i]->cwnd.Get(); // Should be this all the time
    }
}

int
MpTcpSocketBase::LookupSubflow(Ipv4Address src, uint32_t srcPort, Ipv4Address dst, uint32_t dstPort)
{
    NS_LOG_FUNCTION(this);

    NS_ASSERT(m_localAddress == src);
    NS_ASSERT(m_remoteAddress == dst);
    NS_ASSERT(m_localPort == srcPort);
    NS_ASSERT(m_remotePort == dstPort);

    Ptr<MpTcpSubFlow> sFlow = 0;
    uint8_t sFlowIdx = maxSubflows;

    // Walk through the existing subflow container and try to find one with 4-tuple match!
    for (uint32_t i = 0; i < subflows.size(); i++)
    {
        sFlow = subflows[i];
        if (sFlow->sAddr == src && sFlow->dAddr == dst && sFlow->sPort == srcPort &&
            sFlow->dPort == dstPort)
        {
            sFlowIdx = i;
            return sFlowIdx;
        }
    }

    // For now this should be happen only at server side
    NS_ASSERT(server);

    // Recevier would create its new subflow when SYN with MP_JOIN being sent.
    sFlowIdx = subflows.size();
    sFlow = CreateObject<MpTcpSubFlow>();
    sFlow->routeId = subflows[subflows.size() - 1]->routeId + 1;
    sFlow->dAddr = dst;
    sFlow->dPort = dstPort;
    sFlow->sAddr = src;
    sFlow->sPort = srcPort;
    sFlow->MSS = segmentSize;
    sFlow->cwnd = sFlow->MSS;
    sFlow->state = LISTEN;
    sFlow->cnTimeout = m_cnTimeout;
    sFlow->cnRetries = m_synRetries;
    sFlow->cnCount = sFlow->cnRetries;
    sFlow->m_endPoint = m_tcp->Allocate(sFlow->sAddr, sFlow->sPort, sFlow->dAddr, sFlow->dPort);
    if (sFlow->m_endPoint == 0)
        return -1;
    sFlow->m_endPoint->SetRxCallback(
        MakeCallback(&MpTcpSocketBase::ForwardUp, Ptr<MpTcpSocketBase>(this)));
    subflows.insert(subflows.end(), sFlow);
    NS_LOG_UNCOND(this << " LookupSubflow -> Subflow(" << (int)sFlowIdx
                       << ") has created its (src,dst) = (" << sFlow->sAddr << ":" << sFlow->sPort
                       << " , " << sFlow->dAddr << ":" << sFlow->dPort << ")");

    return sFlowIdx;
}

uint8_t
MpTcpSocketBase::getSubflowToUse()
{
    // SCHED
    NS_LOG_FUNCTION(this);
    uint8_t nextSubFlow = 0;
    switch (distribAlgo)
    {
    case Round_Robin:
        nextSubFlow = (lastUsedsFlowIdx + 1) % subflows.size();
        break;
    default:
        break;
    }
    return nextSubFlow;
}

} // namespace ns3
