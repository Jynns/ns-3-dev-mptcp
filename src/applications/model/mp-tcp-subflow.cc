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

#include "mp-tcp-subflow.h"

#include "ns3/simulator.h"

#include <iostream>

NS_LOG_COMPONENT_DEFINE("MpTcpSubflow");

namespace ns3
{

NS_OBJECT_ENSURE_REGISTERED(MpTcpSubFlow);

TypeId
MpTcpSubFlow::GetTypeId(void)
{
    static TypeId tid = TypeId("ns3::MpTcpSubFlow")
                            .SetParent<Object>()
                            .AddConstructor<MpTcpSubFlow>()
                            .AddTraceSource("cWindow",
                                            "The congestion control window to trace.",
                                            MakeTraceSourceAccessor(&MpTcpSubFlow::cwnd),
                                            "ns3::MpTcpSubFlow::cwnd");

    return tid;
}

MpTcpSubFlow::MpTcpSubFlow()
    : routeId(0),
      state(TcpSocket::TcpStates_t::CLOSED),
      sAddr(Ipv4Address::GetZero()),
      sPort(0),
      dAddr(Ipv4Address::GetZero()),
      dPort(0),
      oif(0),
      mapDSN(0),
      m_history(),
      lastMeasuredRtt(Seconds(0.0))
{
    connected = false;
    TxSeqNumber = rand() % 1000;
    RxSeqNumber = 0;
    bandwidth = 0;
    cwnd = 0;
    ssthresh = 65535;
    maxSeqNb = TxSeqNumber - 1;
    highestAck = 0;
    rtt = CreateObjectWithAttributes<RttMeanDeviation>();
    // TODO IMPORTANT
    //   "Alpha", DoubleValue(0.1),
    //   "Beta", DoubleValue(0.1),
    //   "InitialEstimation", Seconds(1.5)
    //);
    // rtt->SetCurrentEstimate(estimate);
    cnRetries = 3;
    Time est = MilliSeconds(200);
    cnTimeout = est;
    initialSequnceNumber = 0;
    m_retxThresh = 3;
    m_inFastRec = false;
    m_limitedTx = false;
    m_dupAckCount = 0;
    PktCount = 0;
    m_recover = SequenceNumber32(0);
    m_gotFin = false;
    AccumulativeAck = false;
    m_limitedTxCount = 0;
}

MpTcpSubFlow::~MpTcpSubFlow()
{
    m_endPoint = 0;
    routeId = 0;
    sAddr = Ipv4Address::GetZero();
    oif = 0;
    state = TcpSocket::TcpStates_t::CLOSED;
    bandwidth = 0;
    cwnd = 0;
    maxSeqNb = 0;
    highestAck = 0;
    for (list<DSNMapping*>::iterator it = mapDSN.begin(); it != mapDSN.end(); ++it)
    {
        DSNMapping* ptrDSN = *it;
        delete ptrDSN;
    }
    mapDSN.clear();
}

bool
MpTcpSubFlow::Finished(void)
{
    return (m_gotFin && m_finSeq.GetValue() < RxSeqNumber);
}

void
MpTcpSubFlow::StartTracing(string traced)
{
    // NS_LOG_UNCOND("("<< routeId << ") MpTcpSubFlow -> starting tracing of: "<< traced);
    TraceConnectWithoutContext(traced,
                               MakeCallback(&MpTcpSubFlow::CwndTracer, this)); //"CongestionWindow"
}

void
MpTcpSubFlow::CwndTracer(uint32_t oldval, uint32_t newval)
{
    // NS_LOG_UNCOND("Subflow "<< routeId <<": Moving cwnd from " << oldval << " to " << newval);
    cwndTracer.push_back(make_pair(Simulator::Now().GetSeconds(), newval));
    sstTracer.push_back(make_pair(Simulator::Now().GetSeconds(), ssthresh));
    // rttTracer.push_back(make_pair(Simulator::Now().GetSeconds(),
    // rtt->GetCurrentEstimate().GetMilliSeconds()));
    // rtoTracer.push_back(make_pair(Simulator::Now().GetSeconds(),
    // rtt->RetransmitTimeout().GetMilliSeconds()));
}

void
MpTcpSubFlow::AddDSNMapping(uint8_t sFlowIdx, uint64_t dSeqNum, uint16_t dLvlLen, uint32_t sflowSeqNum, uint32_t ack/*,
    Ptr<Packet> pkt*/)
{
    NS_LOG_FUNCTION_NOARGS();
    mapDSN.push_back(new DSNMapping(sFlowIdx, dSeqNum, dLvlLen, sflowSeqNum, ack /*, pkt*/));
}

void
MpTcpSubFlow::SetFinSequence(const SequenceNumber32& s)
{
    NS_LOG_FUNCTION(this);
    m_gotFin = true;
    m_finSeq = s;
    if (RxSeqNumber == m_finSeq.GetValue())
        ++RxSeqNumber;
}

void
MpTcpSubFlow::SentSeq(SequenceNumber32 seq, uint32_t size)
{
    NS_LOG_FUNCTION(this);

    // update the history of sequence numbers used to calculate the RTT
    if (seq.GetValue() == TxSeqNumber) // could be replaced with variable isretransmit
    {                                  // This is the next expected one, just log at end
        m_history.emplace_back(seq, size, Simulator::Now());
    }
    else
    { // This is a retransmit, find in list and mark as re-tx
        for (auto i = m_history.begin(); i != m_history.end(); ++i)
        {
            if ((seq >= i->seq) && (seq < (i->seq + SequenceNumber32(i->count))))
            { // Found it
                i->retx = true;
                i->count = ((seq + SequenceNumber32(size)) - i->seq); // And update count in hist
                break;
            }
        }
    }
}

Time
MpTcpSubFlow::AckSeq(SequenceNumber32 ackSeq)
{
    Time m = Time(0.0);

    // An ack has been received, calculate rtt and log this measurement
    // Note we use a linear search (O(n)) for this since for the common
    // case the ack'ed packet will be at the head of the list
    if (!m_history.empty())
    {
        RttHistory& h = m_history.front();
        if (!h.retx && ackSeq >= (h.seq + SequenceNumber32(h.count)))
        { // Ok to use this sample
          // TODO implement TS Option
            /*if (m_timestampEnabled && tcpHeader.HasOption(TcpOption::TS))
            {
                Ptr<const TcpOptionTS> ts;
                ts = DynamicCast<const TcpOptionTS>(tcpHeader.GetOption(TcpOption::TS));
                m = TcpOptionTS::ElapsedTimeFromTsValue(ts->GetEcho());
                if (m.IsZero())
                {
                    NS_LOG_LOGIC("TcpSocketBase::EstimateRtt - RTT calculated from TcpOption::TS "
                                 "is zero, approximating to 1us.");
                    m = MicroSeconds(1);
                }
            }
            else
            {
                m = Simulator::Now() - h.time; // Elapsed time
            }*/
            m = Simulator::Now() - h.time; // Elapsed time
            rtt->Measurement(m);                // Log the measurement
            // ResetMultiplier ();             // the formular for RTO doesnt use a multiplier so
            // this is outdatet (orig:Reset multiplier on valid measurement) m_tcb->m_lastRtt =
            // m_rtt->GetEstimate(); m_tcb->m_minRtt = std::min(m_tcb->m_lastRtt.Get(),
            // m_tcb->m_minRtt);
            //NS_LOG_INFO(this << m_tcb->m_lastRtt << m_tcb->m_minRtt);
        }
    }

    // Now delete all ack history with seq <= ack
    while (!m_history.empty())
    {
        RttHistory& h = m_history.front();
        if ((h.seq + SequenceNumber32(h.count)) > ackSeq)
        {
            break; // Done removing
        }
        m_history.pop_front(); // Remove
    }

    if (!m.IsZero())
    {
        rtt->Measurement(m); // Log the measurement
        // RFC 6298, clause 2.4
        //m_rto = Max(m_rtt->GetEstimate() + Max(m_clockGranularity, m_rtt->GetVariation() * 4),m_minRto);
        //m_tcb->m_lastRtt = m_rtt->GetEstimate();
        //m_tcb->m_minRtt = std::min(m_tcb->m_lastRtt.Get(), m_tcb->m_minRtt);
        //NS_LOG_INFO(this << m_tcb->m_lastRtt << m_tcb->m_minRtt);
    }
    return m;
}

void
MpTcpSubFlow::RttEstimatorReset()
{
    m_history.clear();
    rtt->Reset();
}

DSNMapping*
MpTcpSubFlow::GetunAckPkt()
{
    NS_LOG_FUNCTION(this);
    DSNMapping* ptrDSN = 0;
    for (list<DSNMapping*>::iterator it = mapDSN.begin(); it != mapDSN.end(); ++it)
    {
        DSNMapping* ptr = *it;
        if (ptr->subflowSeqNumber == highestAck + 1)
        {
            ptrDSN = ptr;
            break;
        }
    }
    return ptrDSN;
}
} // namespace ns3
