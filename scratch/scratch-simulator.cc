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
void handler(Ptr<MpTcpSocketBase> m, InetSocketAddress rem)
        {
            m->Connect(rem);
        }

int
main(int argc, char* argv[])
{
    // Config::Set("/NodeList/*/$ns3::TcpL4Protocol/SocketType", TypeIdValue(tid));
    //-> there has to be a valid ns3 congestion algo when creating the socke
    NS_LOG_UNCOND("Scratch Simulator");
    if (1==1)
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

        mp1->Bind();
        mp1->SetRecvCallback(MakeCallback(&ReceivePacket));
        ns3::Address f = mp1->GetBoundNetDevice()->GetAddress();
        std::cout << f << std::endl;
        InetSocketAddress remote = InetSocketAddress(i.GetAddress(0), 4477);
        //mp2->Connect(remote);
        

        Simulator::Schedule(Seconds(2), &handler, mp2, remote);

        NS_LOG_INFO("Run Simulation.");
        Simulator::Stop(Seconds(10.0));
        Simulator::Run();
        Simulator::Destroy();
        NS_LOG_INFO("Done.");
    }
    else
    {
        bool tracing = false;
        uint32_t maxBytes = 0;

        //
        // Allow the user to override any of the defaults at
        // run-time, via command-line arguments
        //
        CommandLine cmd(__FILE__);
        cmd.AddValue("tracing", "Flag to enable/disable tracing", tracing);
        cmd.AddValue("maxBytes", "Total number of bytes for application to send", maxBytes);
        cmd.Parse(argc, argv);

        //
        // Explicitly create the nodes required by the topology (shown above).
        //
        NS_LOG_INFO("Create nodes.");
        NodeContainer nodes;
        nodes.Create(2);

        NS_LOG_INFO("Create channels.");

        //
        // Explicitly create the point-to-point link required by the topology (shown above).
        //
        PointToPointHelper pointToPoint;
        pointToPoint.SetDeviceAttribute("DataRate", StringValue("500Kbps"));
        pointToPoint.SetChannelAttribute("Delay", StringValue("5ms"));

        NetDeviceContainer devices;
        devices = pointToPoint.Install(nodes);

        //
        // Install the internet stack on the nodes
        //
        InternetStackHelper internet;
        internet.Install(nodes);

        //
        // We've got the "hardware" in place.  Now we need to add IP addresses.
        //
        NS_LOG_INFO("Assign IP Addresses.");
        Ipv4AddressHelper ipv4;
        ipv4.SetBase("10.1.1.0", "255.255.255.0");
        Ipv4InterfaceContainer i = ipv4.Assign(devices);

        NS_LOG_INFO("Create Applications.");

        //
        // Create a BulkSendApplication and install it on node 0
        //
        uint16_t port = 9; // well-known echo port number

        BulkSendHelper source("ns3::TcpSocketFactory", InetSocketAddress(i.GetAddress(1), port));
        // Set the amount of data to send in bytes.  Zero is unlimited.
        source.SetAttribute("MaxBytes", UintegerValue(maxBytes));
        ApplicationContainer sourceApps = source.Install(nodes.Get(0));
        sourceApps.Start(Seconds(0.0));
        sourceApps.Stop(Seconds(10.0));

        //
        // Create a PacketSinkApplication and install it on node 1
        //
        PacketSinkHelper sink("ns3::TcpSocketFactory",
                              InetSocketAddress(Ipv4Address::GetAny(), port));
        ApplicationContainer sinkApps = sink.Install(nodes.Get(1));
        sinkApps.Start(Seconds(0.0));
        sinkApps.Stop(Seconds(10.0));

        //
        // Set up tracing if enabled
        //
        if (tracing)
        {
            AsciiTraceHelper ascii;
            pointToPoint.EnableAsciiAll(ascii.CreateFileStream("tcp-bulk-send.tr"));
            pointToPoint.EnablePcapAll("tcp-bulk-send", false);
        }

        //
        // Now, do the actual simulation.
        //
        NS_LOG_INFO("Run Simulation.");
        Simulator::Stop(Seconds(10.0));
        Simulator::Run();
        Simulator::Destroy();
        NS_LOG_INFO("Done.");

        Ptr<PacketSink> sink1 = DynamicCast<PacketSink>(sinkApps.Get(0));
        std::cout << "Total Bytes Received: " << sink1->GetTotalRx() << std::endl;
    }
    return 0;
}
