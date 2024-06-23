/* -*- Mode:C++; c-file-style:"gnu"; indent-tabs-mode:nil; -*- */
/*
 * Copyright (c) 2014 Morteza Kheirkhah
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License version 2 as
 * published by the Free Software Foundation;
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA  02111-1307  USA
 *
 * Author: Morteza Kheirkhah <m.kheirkhah@sussex.ac.uk>
 */

#ifndef MP_TCP_SOCKET_BASE_H
#define MP_TCP_SOCKET_BASE_H

//#include "ns3/mp-tcp-typedefs.h"
#include "ns3/tcp-socket-base.h"
// #include "ns3/gnuplot.h"
#include "mp-tcp-subflow.h"
#include "ns3/output-stream-wrapper.h"
#include "ns3/object-base.h"
#include "ns3/mp-tcp-typedef.h"
#include "ns3/tcp-l4-protocol.h"

using namespace std;
namespace ns3
{
class Ipv4EndPoint;
class Node;
class Packet;

class MpTcpSocketBase : public TcpSocketBase //: public TcpSocketBase
{
public: // public methods

  static TypeId GetTypeId(void);
  MpTcpSocketBase();
  //MpTcpSocketBase(Ptr<Node> node);
  virtual ~MpTcpSocketBase();

  // Public interface for MPTCP
  virtual int Bind();                         // Bind a socket by setting up endpoint in TcpL4Protocol
  virtual int Bind(const Address &address);   // Bind a socket ... to specific add:port; set net device befor 
  virtual int Connect(const Address &address);
  virtual int Connect(Ipv4Address servAddr, uint16_t servPort);  
  virtual int Listen(void);
  virtual int Close(void);                    // Close by app: Kill socket upon tx buffer emptied
  virtual int Close(uint8_t sFlowIdx);        // Closing subflow...
  void SetCongestionCtrlAlgo(CongestionCtrl_t ccalgo);
  void SetSchedulingAlgo(DataDistribAlgo_t ddalgo);
  void SetPathManager(PathManager_t pManagerMode);
  bool SendAllSubflowsFIN(void);
  int FillBuffer(uint32_t size);
  bool SendBufferedData();                    // This would called SendPendingData() - TcpTxBuffer API need to be used in future!
  uint32_t GetTxAvailable();                  // Return available space in sending buffer to application

  // public variables
  // Evaluation & plotting parameters and containers
  double fLowStartTime;
  int mod;
  int MSS;
  int LinkCapacity;
  int totalBytes;
  double RTT;
  double lostRate;
  double TimeScale;
  // Only for plotting purpose
  uint32_t pAck;
  uint32_t FullAcks;
  uint32_t TimeOuts;
  uint32_t FastReTxs;
  uint32_t FastRecoveries;
  bool flowCompletionTime;
  //uint64_t TxBytes;
  uint32_t flowId;
  string flowType;
  string outputFileName;
  double goodput;
  bool m_largePlotting;
  bool m_shortPlotting;
  bool m_alphaPerAck;
  uint32_t m_rGap;
  bool m_shortFlowTCP;


  std::list<uint32_t> sampleList;

  vector<pair<double, double> > totalCWNDtrack;
  vector<pair<double, double> > reTxTrack;
  vector<pair<double, double> > timeOutTrack;
  vector<pair<double, double> > PartialAck;
  vector<pair<double, double> > FullAck;
  vector<pair<double, double> > DupAcks;
  vector<pair<double, double> > PacketDrop;
  vector<pair<double, double> > TxQueue;


protected:
//protected methods
// Implementing some inherited methods from ns3::TcpSocket. No need to comment them!
  virtual void SetSndBufSize (uint32_t size);
  virtual uint32_t GetSndBufSize (void) const;
  virtual void SetRcvBufSize (uint32_t size);
  virtual uint32_t GetRcvBufSize (void) const;
  virtual void SetSSThresh(uint32_t threshold);
  virtual uint32_t GetSSThresh(void) const;
  virtual void SetInitialCwnd(uint32_t cwnd);
  virtual uint32_t GetInitialCwnd(void) const;
  virtual void SetSegSize(uint32_t size);
  virtual uint32_t GetSegSize(void) const;

  //MPTCP connection and subflow setup
  int  SetupCallback(void);  // Setup SetRxCallback & SetRxCallback call back for a host
  void AdvertiseAvailableAddresses(); // Advertise all addresses to the peer, including the already established address.
  void CompleteFork(Ptr<Packet> p, const TcpHeader& h, const Address& fromAddress, const Address& toAddress);
  bool InitiateSubflows();            // Initiate new subflows when FullMesh mode is active
  bool InitiateSingleSubflows(uint16_t); // Initiate new subflows when nDiffPorts is active
  virtual void InitiateMultipleSubflows();
  

  // Transfer operations
  void ForwardUp(Ptr<Packet> p, Ipv4Header header, uint16_t port, Ptr<Ipv4Interface> interface);
  virtual void DoForwardUp(Ptr<Packet> p, Ipv4Header header, uint16_t port, Ptr<Ipv4Interface> interface);
  virtual bool SendPendingData(uint8_t sFlowId = -1);
  virtual void SendEmptyPacket(uint8_t sFlowId, uint8_t flags);
  void SendRST(uint8_t sFlowIdx);
  virtual int SendDataPacket (uint8_t sFlowIdx, uint32_t pktSize, bool withAck);
  virtual bool IsThereRoute(Ipv4Address src, Ipv4Address dst);
  Ptr<NetDevice> FindOutputNetDevice(Ipv4Address); 

  //connection and closing operations
  virtual int DoClose(uint8_t sFlowIdx);
  void CloseAndNotify(uint8_t sFlowIdx);
  void CloseAndNotifyAllSubflows();
  void DeallocateEndPoint(uint8_t sFlowIdx);
  bool CloseMultipathConnection();      // Close MPTCP connection is possible
  void CancelAllSubflowTimers(void);
  void CancelAllTimers(uint8_t sFlowIdx);
  void PeerClose(uint8_t sFlow, Ptr<Packet> p, const TcpHeader& tcpHeader);
  void DoPeerClose(uint8_t sFlowIdx);
  //void CancelAllTimers(uint8_t sFlowIdx);
  void TimeWait(uint8_t sFlowIdx);

//state transition functions
  void ProcessListen  (uint8_t sFlowIdx, Ptr<Packet>, const TcpHeader&, const Address&, const Address&);
  void ProcessListen  (Ptr<Packet> p, const TcpHeader&, const Address&, const Address&);
  void ProcessEstablished (uint8_t sFlowIdx, Ptr<Packet>, const TcpHeader&);
  virtual void ProcessSynSent (uint8_t sFlowIdx, Ptr<Packet>, const TcpHeader&);
  void ProcessSynRcvd (uint8_t sFlowIdx, Ptr<Packet>, const TcpHeader&, const Address&, const Address&);
  void ProcessWait    (uint8_t sFlowIdx, Ptr<Packet>, const TcpHeader&);
  //void ProcessClosing (uint8_t sFlowIdx, Ptr<Packet>, const TcpHeader&);
  void ProcessLastAck (uint8_t sFlowIdx, Ptr<Packet>, const TcpHeader&);
  //uint8_t ProcessOption(Ptr<TcpOption> opt);

  // Window Management
  virtual uint32_t BytesInFlight(uint8_t sFlowIdx);  // Return total bytes in flight of a subflow
  uint16_t AdvertisedWindowSize();
  uint32_t AvailableWindow(uint8_t sFlowIdx);
  

//Managing Data Tx/Rx
  virtual bool ReadOptions (uint8_t sFlowIdx, Ptr<Packet> pkt, const TcpHeader&); // Read option from incoming packets
  virtual bool ReadOptions (Ptr<Packet> pkt, const TcpHeader&); // Read option from incoming packets (Listening Socket only)
  virtual void EstimateRtt (uint8_t sFlowIdx, const TcpHeader&);
  virtual void EstimateRtt (const TcpHeader&);
    // Manage data Tx/Rx
  virtual Ptr<TcpSocketBase> Fork(void);
  virtual void ReceivedAck (uint8_t sFlowIdx, Ptr<Packet>, const TcpHeader&); // Received an ACK packet
  virtual void ReceivedData (uint8_t sFlowIdx, Ptr<Packet>, const TcpHeader&); // Recv of a data, put into buffer, call L7 to get it if necessary
  virtual void DupAck(const TcpHeader& t, uint32_t count);  // Not in operation, it's pure virtual function from TcpSocketBase
  virtual void DupAck(uint8_t sFlowIdx, DSNMapping * ptrDSN);       // Congestion control algorithms -> loss recovery
  virtual void NewACK(uint8_t sFlowIdx, const TcpHeader&, Ptr<TcpOption> opt);
  void NewAckNewReno(uint8_t sFlowIdx, const TcpHeader&, Ptr<TcpOption> opt);
  virtual void DoRetransmit (uint8_t sFlowIdx);
  virtual void DoRetransmit (uint8_t sFlowIdx, DSNMapping* ptrDSN);
  void SetReTxTimeout(uint8_t sFlowIdx);
  void ReTxTimeout(uint8_t sFlowIdx);
  virtual void Retransmit(uint8_t sFlowIdx);
  void LastAckTimeout(uint8_t sFlowIdx);
  void DiscardUpTo(uint8_t sFlowIdx, uint32_t ack);

// Re-ordering buffer
  bool FindPacketFromUnOrdered(uint8_t sFlowIdx);
  bool StoreUnOrderedData(DSNMapping *ptr);
  void ReadUnOrderedData();

// Congestion control
  virtual void OpenCWND(uint8_t sFlowIdx, uint32_t ackedBytes);
  void ReduceCWND(uint8_t sFlowIdx, DSNMapping* ptrDSN);
  virtual void calculateAlpha();
  virtual void calculateTotalCWND();
  uint32_t compute_total_window();
  uint32_t compute_a_scaled();
  double compute_alfa();
  void window_changed();


//helper function 

  void IsLastAck();
  // Helper functions -> main operations
  //uint8_t LookupByAddrs(Ipv4Address src, Ipv4Address dst); // Called by Forwardup() to find the right subflow for incoing packet
  virtual int LookupSubflow(Ipv4Address src, uint32_t srcPort, Ipv4Address dst, uint32_t dstPort); // LookupBy4-Tuple

  virtual uint8_t getSubflowToUse();  // Called by SendPendingData() to get a subflow based on round robin algorithm
  //bool IsThereRoute(Ipv4Address src, Ipv4Address dst);     // Called by InitiateSubflow & LookupByAddrs and Connect to check whether there is route between a pair of addresses.
  //bool IsLocalAddress(Ipv4Address addr);
  //bool IsRemoteAddress(Ipv4Address addr);
  //Ptr<NetDevice> FindOutputNetDevice(Ipv4Address);         // Find Netdevice object of specific IP address.
  //DSNMapping* getAckedSegment(uint8_t sFlowIdx, uint32_t ack);
  DSNMapping* getSegmentOfACK(uint8_t sFlowIdx, uint32_t ack);
  //void SendAccumulativeAck(uint8_t sFlowIdx);
  // Helper functions -> evaluation and debugging
  //void PrintIpv4AddressFromIpv4Interface(Ptr<Ipv4Interface>, int32_t);
  //std::string PrintCC(uint32_t cc);
  //void getQueuePkt(Ipv4Address addr);

  string TcpFlagPrinter(uint8_t);

//protected variables 
  // TODO is this really necessary?
  friend class Tcp;

   // Uniform Random Variable
  // uint16_t GetRandom16();
  // uint32_t GetRandom32();
  // uint32_t GetRandom(uint32_t, uint32_t);
  double drand();
  // uint32_t GetEstSubflows();


  CongestionCtrl_t m_algocc; 
  DataDistribAlgo_t m_scheduler;
  PathManager_t m_pathManager;
  
  // MPTCP connection parameters
  //Ptr<Node>          m_node;
  //Ipv4EndPoint*      m_endPoint;
  //Ptr<TcpL4Protocol> m_mptcp;
  Ipv4Address        m_localAddress;
  Ipv4Address        m_remoteAddress;
  uint16_t           m_localPort;
  uint16_t           m_remotePort;
  uint8_t            currentSublow;

  // MultiPath related parameters
  MpStates_t mpSendState;
  MpStates_t mpRecvState;
  bool mpEnabled;
  bool mpTokenRegister;
  bool addrAdvertised;
  uint32_t localToken;
  uint32_t remoteToken;
  uint32_t unOrdMaxSize;
  uint8_t  maxSubflows;
  uint8_t  lastUsedsFlowIdx;

  // MPTCP containers  vector<Ptr<MpTcpSubFlow> > subflows;
  vector<Ptr<MpTcpSubFlow> > subflows;
  vector<MpTcpAddressInfo *> localAddrs;
  vector<MpTcpAddressInfo *> remoteAddrs;
  list<DSNMapping *> unOrdered;

  // Congestion control
  double alpha;
  uint32_t a;
  double _e;


  uint32_t totalCwnd;
  DataDistribAlgo_t distribAlgo; // Algorithm for Data Distribution
  // PathManager_t pathManager;        // Mechanism for subflow establishement

  // Window management variables
  uint32_t m_ssThresh;           // Slow start threshold
  uint32_t m_initialCWnd;        // Initial congestion window value
  uint32_t remoteRecvWnd;        // Flow control window at remote side
  uint32_t segmentSize;          // Segment size
  uint64_t nextTxSequence;       // Next expected sequence number to send in connection level
  uint64_t nextRxSequence;       // Next expected sequence number to receive in connection level

  // Buffer management
  DataBuffer sendingBuffer;
  DataBuffer recvingBuffer;

  bool client;
  bool server;

};

}   //namespace ns3

#endif /* MP_TCP_SOCKET_BASE_H */
