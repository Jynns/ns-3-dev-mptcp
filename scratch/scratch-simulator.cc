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
    //TODO move this to function
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

int
main(int argc, char* argv[])
{
    // Config::Set("/NodeList/*/$ns3::TcpL4Protocol/SocketType", TypeIdValue(tid));
    //-> there has to be a valid ns3 congestion algo when creating the socke
    NS_LOG_UNCOND("Scratch Simulator");
    if (1 == 1)
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

        TcpHeader source;
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
        std::cout << ak << af;

        mp1->Listen();
        Simulator::Schedule(Seconds(2), &handlerConnect, mp2, remote);
        Simulator::Schedule(Seconds(2.5), &handlerSend, mp2);

        NS_LOG_INFO("Run Simulation.");
        Simulator::Stop(Seconds(10.0));
        Simulator::Run();
        Simulator::Destroy();
        NS_LOG_INFO("Done.");
    }
    return 0;
}
