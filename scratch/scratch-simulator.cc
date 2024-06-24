/*
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
 */

#include "ns3/applications-module.h"
#include "ns3/core-module.h"
#include "ns3/internet-module.h"
#include "ns3/internet-stack-helper.h"
#include "ns3/ipv4-address-helper.h"
#include "ns3/mp-tcp-socket-base.h"
#include "ns3/network-module.h"
#include "ns3/node-container.h"
#include "ns3/packet-sink.h"
#include "ns3/point-to-point-helper.h"
#include "ns3/point-to-point-module.h"

#include <fstream>
#include <string>

using namespace ns3;

NS_LOG_COMPONENT_DEFINE("ScratchSimulator");

void
ReceivePacket(Ptr<Socket> socket)
{
    NS_LOG_INFO("Received one packet!");
    Ptr<Packet> packet = socket->Recv();
    SocketIpTosTag tosTag;
    if (packet->RemovePacketTag(tosTag))
    {
        NS_LOG_INFO(" TOS = " << (uint32_t)tosTag.GetTos());
    }
    SocketIpTtlTag ttlTag;
    if (packet->RemovePacketTag(ttlTag))
    {
        NS_LOG_INFO(" TTL = " << (uint32_t)ttlTag.GetTtl());
    }
}

void
handlerConnect(Ptr<MpTcpSocketBase> m, InetSocketAddress rem)
{
    int connectionResult = m->Connect(rem);
    if (connectionResult == 0)
    {
        NS_LOG_UNCOND("Connection sucessful start sending Data");
    }
}

void
handlerSend(Ptr<MpTcpSocketBase> m_socket)
{
    // TODO move this to function
    uint32_t m_totBytes = 0;
    uint32_t m_maxBytes = 1000000;
    uint32_t m_sendSize = 140000;

    NS_LOG_DEBUG("m_totBytes: " << m_totBytes << " maxByte: " << m_maxBytes << " GetTxAvailable: "
                                << m_socket->GetTxAvailable() << " SendSize: " << m_sendSize);

    // while (m_totBytes < m_maxBytes && m_socket->GetTxAvailable())

    while ((m_maxBytes == 0 && m_socket->GetTxAvailable()) ||
           (m_totBytes < m_maxBytes && m_socket->GetTxAvailable()))
    { // Time to send more new data into MPTCP socket buffer
        uint32_t toSend = m_sendSize;
        if (m_maxBytes > 0)
        {
            uint32_t tmp = std::min(m_sendSize, m_maxBytes - m_totBytes);
            toSend = std::min(tmp, m_socket->GetTxAvailable());
        }
        else
        {
            toSend = std::min(m_sendSize, m_socket->GetTxAvailable());
        }
        // toSend = std::min(toSend, m_bufferSize);
        // int actual = m_socket->FillBuffer(&m_data[toSend], toSend); // TODO Change m_totalBytes
        // to toSend
        int actual = m_socket->FillBuffer(toSend); // TODO Change m_totalBytes to toSend
        m_totBytes += actual;
        NS_LOG_DEBUG("toSend: " << toSend << " actual: " << actual << " totalByte: " << m_totBytes);
        m_socket->SendBufferedData();
    }
    if (m_totBytes == m_maxBytes) // && m_connected)
    {
        m_socket->Close();
        // m_connected = false;
    }
}

static void 
CwndTracer (uint32_t oldval, uint32_t newval)
{
    NS_LOG_INFO ("Moving cwnd from " << oldval << " to " << newval);
}

int
main(int argc, char* argv[])
{
    // Config::Set("/NodeList/*/$ns3::TcpL4Protocol/SocketType", TypeIdValue(tid));
    //-> there has to be a valid ns3 congestion algo when creating the socke
    int mode = 3;
    NS_LOG_UNCOND("Scratch Simulator");
    if (mode == 1)
    {
        // Config::SetDefault("ns3::Ipv4GlobalRouting::FlowEcmpRouting", BooleanValue(true));
        Config::SetDefault("ns3::TcpSocket::SegmentSize", UintegerValue(1400));
        Config::SetDefault("ns3::TcpSocket::DelAckCount", UintegerValue(0));
        // Config::SetDefault("ns3::DropTailQueue::Mode", StringValue("QUEUE_MODE_PACKETS"));
        // Config::SetDefault("ns3::DropTailQueue::MaxPackets", UintegerValue(100));
        Config::SetDefault("ns3::TcpL4Protocol::SocketType",
                           TypeIdValue(MpTcpSocketBase::GetTypeId()));
        Config::SetDefault("ns3::MpTcpSocketBase::MaxSubflows", UintegerValue(8));

        NodeContainer nodes;
        nodes.Create(2);

        PointToPointHelper pointToPoint;
        pointToPoint.SetDeviceAttribute("DataRate", StringValue("5Mbps"));
        pointToPoint.SetChannelAttribute("Delay", StringValue("2ms"));
        NetDeviceContainer devices = pointToPoint.Install(nodes);

        InternetStackHelper internet;
        internet.Install(nodes);

        Ipv4AddressHelper ipv4;
        ipv4.SetBase("10.1.1.0", "255.255.255.0");
        Ipv4InterfaceContainer i = ipv4.Assign(devices);

        TypeId tid = TypeId::LookupByName("ns3::TcpNewReno");

        Ptr<MpTcpSocketBase> mp1 = DynamicCast<MpTcpSocketBase>(
            Socket::CreateSocket(nodes.Get(0), TcpSocketFactory::GetTypeId()));
        Ptr<MpTcpSocketBase> mp2 = DynamicCast<MpTcpSocketBase>(
            Socket::CreateSocket(nodes.Get(1), TcpSocketFactory::GetTypeId()));

        mp1->BindToNetDevice(devices.Get(0));
        mp2->BindToNetDevice(devices.Get(1));

        // mp1->Bind();
        mp2->Bind();
        mp1->SetRecvCallback(MakeCallback(&ReceivePacket));
        ns3::Address f = mp1->GetBoundNetDevice()->GetAddress();
        std::cout << f << std::endl;
        InetSocketAddress remote = InetSocketAddress(i.GetAddress(0), 4477);
        mp1->Bind(remote);
        // mp2->Connect(remote);

        /*TcpHeader source;
        TcpHeader destination;
        Buffer buffer;
        buffer.AddAtStart(40);

        Buffer::Iterator it = buffer.Begin();
        source.AppendOption(CreateObject<MpTcpOptionMultiPathCabable>(12));
        source.Serialize(it);

        it = buffer.Begin();
        destination.Deserialize(it);
        bool af = destination.HasOption(TcpOption::Kind::MP_MPC);
        uint32_t ak = DynamicCast<const MpTcpOptionMultiPathCabable>(
                          destination.GetOption(TcpOption::Kind::MP_MPC))
                          ->m_senderToken;
        std::cout << ak << af;*/

        mp1->Listen();
        Simulator::Schedule(Seconds(2), &handlerConnect, mp2, remote);
        Simulator::Schedule(Seconds(2.5), &handlerSend, mp2);

        NS_LOG_INFO("Run Simulation.");
        Simulator::Stop(Seconds(10.0));
        Simulator::Run();
        Simulator::Destroy();
        NS_LOG_INFO("Done.");
    }
    else if(mode == 2)
    {
        // new topology m2 --dev0-- n --dev1-- m1
        // Config::SetDefault("ns3::Ipv4GlobalRouting::FlowEcmpRouting", BooleanValue(true));
        Config::SetDefault("ns3::TcpSocket::SegmentSize", UintegerValue(1400));
        Config::SetDefault("ns3::TcpSocket::DelAckCount", UintegerValue(0));
        // Config::SetDefault("ns3::DropTailQueue::Mode", StringValue("QUEUE_MODE_PACKETS"));
        // Config::SetDefault("ns3::DropTailQueue::MaxPackets", UintegerValue(100));
        Config::SetDefault("ns3::TcpL4Protocol::SocketType",
                           TypeIdValue(MpTcpSocketBase::GetTypeId()));
        Config::SetDefault("ns3::MpTcpSocketBase::MaxSubflows", UintegerValue(8));
        NodeContainer m2_n;
        m2_n.Create(2); // create m2 and n

        NodeContainer n_m1;
        n_m1.Add(m2_n.Get(1)); // add n to second node container
        n_m1.Create(1);        // create m1 node

        PointToPointHelper p2p;
        p2p.SetDeviceAttribute("DataRate", DataRateValue(DataRate(10000000)));
        p2p.SetChannelAttribute("Delay", TimeValue(MilliSeconds(10)));
        NetDeviceContainer dev0 = p2p.Install(m2_n);
        NetDeviceContainer dev1 = p2p.Install(n_m1);

        InternetStackHelper internet;
        internet.InstallAll();

        Ipv4AddressHelper ipv4;
        ipv4.SetBase("10.1.3.0", "255.255.255.0");
        ipv4.Assign(dev0);
        ipv4.SetBase("10.1.2.0", "255.255.255.0");
        Ipv4InterfaceContainer ipInterfs = ipv4.Assign(dev1);

        Ipv4GlobalRoutingHelper::PopulateRoutingTables ();

        Ptr<MpTcpSocketBase> mp1 = DynamicCast<MpTcpSocketBase>(
            Socket::CreateSocket(n_m1.Get(1), TcpSocketFactory::GetTypeId()));
        Ptr<MpTcpSocketBase> mp2 = DynamicCast<MpTcpSocketBase>(
            Socket::CreateSocket(m2_n.Get(0), TcpSocketFactory::GetTypeId()));

        
        mp2->BindToNetDevice(dev0.Get(0));
        mp1->BindToNetDevice(dev1.Get(1));

        // mp1->Bind();
        mp2->Bind();
        mp1->SetRecvCallback(MakeCallback(&ReceivePacket));
        ns3::Address f = mp1->GetBoundNetDevice()->GetAddress();
        std::cout << f << std::endl;
        InetSocketAddress remote = InetSocketAddress(ipInterfs.GetAddress(1), 4477);
        mp1->Bind(remote);
        mp1->Listen();

        Simulator::Schedule(Seconds(2), &handlerConnect, mp2, remote);
        Simulator::Schedule(Seconds(2.5), &handlerSend, mp2);
        Config::ConnectWithoutContext ("/NodeList/0/$ns3::TcpL4Protocol/SocketList/0/CongestionWindow", MakeCallback (&CwndTracer));

        NS_LOG_INFO("Run Simulation.");
        Simulator::Stop(Seconds(20.0));
        Simulator::Run();
        Simulator::Destroy();
        NS_LOG_INFO("Done.");
    }else if(mode == 3){
        // new topology m2
        //    10.1.3.0
        //  |-----1------|      (main flow)
        //  m2           m1
        //  |-----2------|      (bottle neck)
        //    10.1.2.0
        // Config::SetDefault("ns3::Ipv4GlobalRouting::FlowEcmpRouting", BooleanValue(true));
        Config::SetDefault("ns3::TcpSocket::SegmentSize", UintegerValue(1400));
        Config::SetDefault("ns3::TcpSocket::DelAckCount", UintegerValue(0));
        // Config::SetDefault("ns3::DropTailQueue::Mode", StringValue("QUEUE_MODE_PACKETS"));
        // Config::SetDefault("ns3::DropTailQueue::MaxPackets", UintegerValue(100));
        Config::SetDefault("ns3::TcpL4Protocol::SocketType",
                           TypeIdValue(MpTcpSocketBase::GetTypeId()));
        Config::SetDefault("ns3::MpTcpSocketBase::MaxSubflows", UintegerValue(8));
        Config::SetDefault("ns3::MpTcpSocketBase::PathManagement", StringValue("FullMesh"));
        NodeContainer m2m1;
        m2m1.Create(2);

        PointToPointHelper p1;
        p1.SetDeviceAttribute("DataRate", DataRateValue(DataRate(10000000)));
        p1.SetChannelAttribute("Delay", TimeValue(MilliSeconds(10)));
        NetDeviceContainer dev1 = p1.Install(m2m1);

        PointToPointHelper p2;
        p2.SetDeviceAttribute("DataRate", DataRateValue(DataRate(10000)));
        p2.SetChannelAttribute("Delay", TimeValue(MilliSeconds(20)));
        NetDeviceContainer dev2 = p2.Install(m2m1);


        InternetStackHelper internet;
        internet.InstallAll();

        Ipv4AddressHelper ipv4;
        ipv4.SetBase("10.1.3.0", "255.255.255.0");
        Ipv4InterfaceContainer ipInterfs = ipv4.Assign(dev1);
        ipv4.SetBase("10.1.2.0", "255.255.255.0");
        ipv4.Assign(dev2);

        Ipv4GlobalRoutingHelper::PopulateRoutingTables ();

        Ptr<MpTcpSocketBase> mp1 = DynamicCast<MpTcpSocketBase>(
            Socket::CreateSocket(m2m1.Get(1), TcpSocketFactory::GetTypeId()));
        Ptr<MpTcpSocketBase> mp2 = DynamicCast<MpTcpSocketBase>(
            Socket::CreateSocket(m2m1.Get(0), TcpSocketFactory::GetTypeId()));
        mp1->SetPathManager(FullMesh);   // for some reason the default argument is ignored TODO URGENT FIX
        mp2->SetPathManager(FullMesh);        

        //Bind to device of main flow
        mp2->BindToNetDevice(dev1.Get(0));
        mp1->BindToNetDevice(dev1.Get(1));

        mp2->Bind(); // bind call for MPTCP 
        ns3::Address f = mp2->GetBoundNetDevice()->GetAddress();
        std::cout << "Bound Address mp2 "<< f << std::endl;

        mp1->SetRecvCallback(MakeCallback(&ReceivePacket));
        InetSocketAddress remote = InetSocketAddress(ipInterfs.GetAddress(1), 4477);
        mp1->Bind(remote);
        f = mp1->GetBoundNetDevice()->GetAddress();
        std::cout << "Bound Address mp1 "<< f << std::endl;

        mp1->Listen();

        Simulator::Schedule(Seconds(2), &handlerConnect, mp2, remote);
        Simulator::Schedule(Seconds(2.5), &handlerSend, mp2);
        Config::ConnectWithoutContext ("/NodeList/0/$ns3::TcpL4Protocol/SocketList/0/CongestionWindow", MakeCallback (&CwndTracer));

        NS_LOG_INFO("Run Simulation.");
        Simulator::Stop(Seconds(20.0));
        Simulator::Run();
        Simulator::Destroy();
    }
    return 0;
}
