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
//#include "mp-tcp-subflow.h"
#include "ns3/output-stream-wrapper.h"

#define A 1
#define B 2
#define A_SCALE 512

using namespace std;
namespace ns3
{
class Ipv4EndPoint;
class Node;
class Packet;
class TcpL4Protocol;

class MpTcpSocketBase //: public TcpSocketBase
{
public: // public methods

  static TypeId GetTypeId(void);
  MpTcpSocketBase();
  MpTcpSocketBase(Ptr<Node> node);
  virtual ~MpTcpSocketBase();

  void SetCongestionCtrlAlgo(CongestionCtrl_t ccalgo);
  void SetSchedulingAlgo(DataDistribAlgo_t ddalgo);
  void SetPathManager(PathManager_t pManagerMode);


  uint32_t flowId;
  string flowType;
  string outputFileName;
  double goodput;
  bool m_largePlotting;
  bool m_shortPlotting;
  bool m_alphaPerAck;
  uint32_t m_rGap;
  bool m_shortFlowTCP;

protected:
  CongestionCtrl_t m_algocc; 
  DataDistribAlgo_t m_scheduler;
  PathManager_t m_pathManager;
  
  bool mpEnabled;
  bool mpTokenRegister;
  bool addrAdvertised;
  uint32_t localToken;
  uint32_t remoteToken;
  uint32_t unOrdMaxSize;
  uint8_t  maxSubflows;
  uint8_t  lastUsedsFlowIdx;

  // MPTCP containers
  vector<Ptr<MpTcpSubFlow> > subflows;

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


};

}   //namespace ns3

#endif /* MP_TCP_SOCKET_BASE_H */
