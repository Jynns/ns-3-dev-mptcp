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
  // Transfer operations
  //void ForwardUp(Ptr<Packet> p, Ipv4Header header, uint16_t port, Ptr<Ipv4Interface> interface);
  //virtual void DoForwardUp(Ptr<Packet> p, Ipv4Header header, uint16_t port, Ptr<Ipv4Interface> interface);
  //virtual bool SendPendingData(uint8_t sFlowId = -1);
  virtual void SendEmptyPacket(uint8_t sFlowId, uint8_t flags);
  void SendRST(uint8_t sFlowIdx);
  //virtual int SendDataPacket (uint8_t sFlowIdx, uint32_t pktSize, bool withAck);
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
  //void CancelAllTimers(uint8_t sFlowIdx);

// Re-ordering buffer
  bool FindPacketFromUnOrdered(uint8_t sFlowIdx);


//helper function 
  string TcpFlagPrinter(uint8_t);

//protected variables 
  // TODO is this really necessary?
  friend class Tcp;

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
  CongestionCtrl_t AlgoCC;       // Algorithm for Congestion Control
  DataDistribAlgo_t distribAlgo; // Algorithm for Data Distribution
  PathManager_t pathManager;        // Mechanism for subflow establishement

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
