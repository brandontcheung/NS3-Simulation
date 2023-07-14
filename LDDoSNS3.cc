/*
 *
 * Modified from : https://github.com/samvid25/Low-Rate-TCP-DoS-Attack/pull/1
 */

// The Topology contains 5 nodes as follows:
// 0 -> alice (sender)
// 1 -> eve1 (attacker)
// 2 -> eve1 (attacker)
// 3 -> eve1 (attacker)
// 4 -> eve1 (attacker)
// 5 -> eve1 (attacker)
// 6 -> eve1 (attacker)
// 7 -> eve1 (attacker)
// 8 -> eve1 (attacker)
// 9 -> switch (common switch between alice and eve nodes)
// 10 -> switch (switch conneced to bob)
// 11 -> bob (receiver)

// This will create a .xml . Which can be parsed in NetAnim. 


#include "ns3/mobility-module.h"
#include "ns3/nstime.h"
#include "ns3/core-module.h"
#include "ns3/network-module.h"
#include "ns3/internet-module.h"
#include "ns3/point-to-point-module.h"
#include "ns3/applications-module.h"
#include "ns3/ipv4-global-routing-helper.h"
#include "ns3/netanim-module.h"

#define TCP_SINK_PORT 9000
#define UDP_SINK_PORT 9001

//parameters to change
#define BULK_SEND_MAX_BYTES 2097152
#define ATTACKER_DoS_RATE "20480kb/s"
#define MAX_SIMULATION_TIME 30.0

using namespace ns3;

NS_LOG_COMPONENT_DEFINE("TcpHighRateDoSAttack");

int main(int argc, char *argv[])
{
    CommandLine cmd;
    cmd.Parse(argc, argv);

    Time::SetResolution(Time::NS);
    LogComponentEnable("UdpEchoClientApplication", LOG_LEVEL_INFO);
    LogComponentEnable("UdpEchoServerApplication", LOG_LEVEL_INFO);

    NodeContainer nodes;
    nodes.Create(12);

    // Define the Point-To-Point Links (Helpers) and their Paramters
    PointToPointHelper pp1, pp2;
    pp1.SetDeviceAttribute("DataRate", StringValue("100Mbps"));
    pp1.SetChannelAttribute("Delay", StringValue("1ms"));

    pp2.SetDeviceAttribute("DataRate", StringValue("1.5Mbps"));
    pp2.SetChannelAttribute("Delay", StringValue("20ms"));

    // Install the Point-To-Point Connections between Nodes
    NetDeviceContainer d09, d19, d29, d39, d49, d59, d69, d79, d89, d910, d1011;
    d09 = pp1.Install(nodes.Get(0), nodes.Get(9));
    d19 = pp1.Install(nodes.Get(1), nodes.Get(9));
    d29 = pp1.Install(nodes.Get(2), nodes.Get(9));
    d39 = pp1.Install(nodes.Get(3), nodes.Get(9));
    d49 = pp1.Install(nodes.Get(4), nodes.Get(9));
    d59 = pp1.Install(nodes.Get(5), nodes.Get(9));
    d69 = pp1.Install(nodes.Get(6), nodes.Get(9));
    d79 = pp1.Install(nodes.Get(7), nodes.Get(9));
    d89 = pp1.Install(nodes.Get(8), nodes.Get(9));
    d910 = pp2.Install(nodes.Get(9), nodes.Get(10));
    d1011 = pp1.Install(nodes.Get(10), nodes.Get(11));

    InternetStackHelper stack;
    stack.Install(nodes);

    Ipv4AddressHelper a09, a19, a29, a39, a49, a59, a69, a79, a89, a910, a1011;
    a09.SetBase("10.1.1.0", "255.255.255.0");
    a19.SetBase("10.1.2.0", "255.255.255.0");
    a29.SetBase("10.1.3.0", "255.255.255.0");
    a39.SetBase("10.1.4.0", "255.255.255.0");
    a49.SetBase("10.1.5.0", "255.255.255.0");
    a59.SetBase("10.1.6.0", "255.255.255.0");
    a69.SetBase("10.1.7.0", "255.255.255.0");
    a79.SetBase("10.1.8.0", "255.255.255.0");
    a89.SetBase("10.1.9.0", "255.255.255.0");
    a910.SetBase("10.1.10.0", "255.255.255.0");
    a1011.SetBase("10.1.11.0", "255.255.255.0");

    Ipv4InterfaceContainer i09, i19, i29, i39, i49, i59, i69, i79, i89, i910, i1011;
    i09 = a09.Assign(d09);
    i19 = a19.Assign(d19);
    i29 = a29.Assign(d29);
    i39 = a39.Assign(d39);
    i49 = a49.Assign(d49);
    i59 = a59.Assign(d59);
    i69 = a69.Assign(d69);
    i79 = a79.Assign(d79);
    i89 = a89.Assign(d89);
    i910 = a910.Assign(d910);
    i1011 = a1011.Assign(d1011);

    // Attacker application 1
    OnOffHelper onoff("ns3::UdpSocketFactory", Address(InetSocketAddress(i1011.GetAddress(1), UDP_SINK_PORT)));
    onoff.SetConstantRate(DataRate(ATTACKER_DoS_RATE));
    onoff.SetAttribute("OnTime", StringValue("ns3::ConstantRandomVariable[Constant=30]"));
    onoff.SetAttribute("OffTime", StringValue("ns3::ConstantRandomVariable[Constant=0]"));
    ApplicationContainer onOffApp = onoff.Install(nodes.Get(1));
    onOffApp.Start(Seconds(0.0));
    onOffApp.Stop(Seconds(MAX_SIMULATION_TIME));

    // Attacker application 2
    OnOffHelper onoff("ns3::UdpSocketFactory", Address(InetSocketAddress(i1011.GetAddress(1), UDP_SINK_PORT)));
    onoff.SetConstantRate(DataRate(ATTACKER_DoS_RATE));
    onoff.SetAttribute("OnTime", StringValue("ns3::ConstantRandomVariable[Constant=30]"));
    onoff.SetAttribute("OffTime", StringValue("ns3::ConstantRandomVariable[Constant=0]"));
    ApplicationContainer onOffApp = onoff.Install(nodes.Get(2));
    onOffApp.Start(Seconds(0.0));
    onOffApp.Stop(Seconds(MAX_SIMULATION_TIME));

    // Attacker application 3
    OnOffHelper onoff("ns3::UdpSocketFactory", Address(InetSocketAddress(i1011.GetAddress(1), UDP_SINK_PORT)));
    onoff.SetConstantRate(DataRate(ATTACKER_DoS_RATE));
    onoff.SetAttribute("OnTime", StringValue("ns3::ConstantRandomVariable[Constant=30]"));
    onoff.SetAttribute("OffTime", StringValue("ns3::ConstantRandomVariable[Constant=0]"));
    ApplicationContainer onOffApp = onoff.Install(nodes.Get(3));
    onOffApp.Start(Seconds(0.0));
    onOffApp.Stop(Seconds(MAX_SIMULATION_TIME));

    // Attacker application 4
    OnOffHelper onoff("ns3::UdpSocketFactory", Address(InetSocketAddress(i1011.GetAddress(1), UDP_SINK_PORT)));
    onoff.SetConstantRate(DataRate(ATTACKER_DoS_RATE));
    onoff.SetAttribute("OnTime", StringValue("ns3::ConstantRandomVariable[Constant=30]"));
    onoff.SetAttribute("OffTime", StringValue("ns3::ConstantRandomVariable[Constant=0]"));
    ApplicationContainer onOffApp = onoff.Install(nodes.Get(4));
    onOffApp.Start(Seconds(0.0));
    onOffApp.Stop(Seconds(MAX_SIMULATION_TIME));

    // Attacker application 5
    OnOffHelper onoff("ns3::UdpSocketFactory", Address(InetSocketAddress(i1011.GetAddress(1), UDP_SINK_PORT)));
    onoff.SetConstantRate(DataRate(ATTACKER_DoS_RATE));
    onoff.SetAttribute("OnTime", StringValue("ns3::ConstantRandomVariable[Constant=30]"));
    onoff.SetAttribute("OffTime", StringValue("ns3::ConstantRandomVariable[Constant=0]"));
    ApplicationContainer onOffApp = onoff.Install(nodes.Get(5));
    onOffApp.Start(Seconds(0.0));
    onOffApp.Stop(Seconds(MAX_SIMULATION_TIME));

    // Attacker application 6
    OnOffHelper onoff("ns3::UdpSocketFactory", Address(InetSocketAddress(i1011.GetAddress(1), UDP_SINK_PORT)));
    onoff.SetConstantRate(DataRate(ATTACKER_DoS_RATE));
    onoff.SetAttribute("OnTime", StringValue("ns3::ConstantRandomVariable[Constant=30]"));
    onoff.SetAttribute("OffTime", StringValue("ns3::ConstantRandomVariable[Constant=0]"));
    ApplicationContainer onOffApp = onoff.Install(nodes.Get(6));
    onOffApp.Start(Seconds(0.0));
    onOffApp.Stop(Seconds(MAX_SIMULATION_TIME));

    // Attacker application 7
    OnOffHelper onoff("ns3::UdpSocketFactory", Address(InetSocketAddress(i1011.GetAddress(1), UDP_SINK_PORT)));
    onoff.SetConstantRate(DataRate(ATTACKER_DoS_RATE));
    onoff.SetAttribute("OnTime", StringValue("ns3::ConstantRandomVariable[Constant=30]"));
    onoff.SetAttribute("OffTime", StringValue("ns3::ConstantRandomVariable[Constant=0]"));
    ApplicationContainer onOffApp = onoff.Install(nodes.Get(7));
    onOffApp.Start(Seconds(0.0));
    onOffApp.Stop(Seconds(MAX_SIMULATION_TIME));

    // Attacker application 8
    OnOffHelper onoff("ns3::UdpSocketFactory", Address(InetSocketAddress(i1011.GetAddress(1), UDP_SINK_PORT)));
    onoff.SetConstantRate(DataRate(ATTACKER_DoS_RATE));
    onoff.SetAttribute("OnTime", StringValue("ns3::ConstantRandomVariable[Constant=30]"));
    onoff.SetAttribute("OffTime", StringValue("ns3::ConstantRandomVariable[Constant=0]"));
    ApplicationContainer onOffApp = onoff.Install(nodes.Get(8));
    onOffApp.Start(Seconds(0.0));
    onOffApp.Stop(Seconds(MAX_SIMULATION_TIME));

    // Sender Application (Packets generated by this application are throttled)
    BulkSendHelper bulkSend("ns3::TcpSocketFactory", InetSocketAddress(i1011.GetAddress(1), TCP_SINK_PORT));
    bulkSend.SetAttribute("MaxBytes", UintegerValue(BULK_SEND_MAX_BYTES));
    ApplicationContainer bulkSendApp = bulkSend.Install(nodes.Get(0));
    bulkSendApp.Start(Seconds(0.0));
    bulkSendApp.Stop(Seconds(MAX_SIMULATION_TIME - 10));

    // UDPSink on receiver side (Only for analysis purpose)
    PacketSinkHelper UDPsink("ns3::UdpSocketFactory",
                             Address(InetSocketAddress(Ipv4Address::GetAny(), UDP_SINK_PORT)));
    ApplicationContainer UDPSinkApp = UDPsink.Install(nodes.Get(11));
    UDPSinkApp.Start(Seconds(0.0));
    UDPSinkApp.Stop(Seconds(MAX_SIMULATION_TIME));

    // TCP Sink Application on receviver side
    PacketSinkHelper TCPsink("ns3::TcpSocketFactory",
                             InetSocketAddress(Ipv4Address::GetAny(), TCP_SINK_PORT));
    ApplicationContainer TCPSinkApp = TCPsink.Install(nodes.Get(11));
    TCPSinkApp.Start(Seconds(0.0));
    TCPSinkApp.Stop(Seconds(MAX_SIMULATION_TIME));

    Ipv4GlobalRoutingHelper::PopulateRoutingTables();

    // pp1.EnablePcapAll("PCAPs/tcplow");

    //Simulation NetAnim
    MobilityHelper mobility;

    mobility.SetPositionAllocator("ns3::GridPositionAllocator",
                                  "MinX", DoubleValue(0.0), "MinY", DoubleValue(0.0), "DeltaX", DoubleValue(5.0), "DeltaY", DoubleValue(10.0),
                                  "GridWidth", UintegerValue(5), "LayoutType", StringValue("RowFirst"));

    mobility.SetMobilityModel("ns3::ConstantPositionMobilityModel");

    mobility.Install(nodes);

    AnimationInterface anim("LDDoSNS3.xml");

    ns3::AnimationInterface::SetConstantPosition(nodes.Get(0), 0, 0);
    ns3::AnimationInterface::SetConstantPosition(nodes.Get(1), 0, 20);
    ns3::AnimationInterface::SetConstantPosition(nodes.Get(2), 0, 40);
    ns3::AnimationInterface::SetConstantPosition(nodes.Get(3), 0, 60);
    ns3::AnimationInterface::SetConstantPosition(nodes.Get(4), 0, 80);
    ns3::AnimationInterface::SetConstantPosition(nodes.Get(5), 0, 100);
    ns3::AnimationInterface::SetConstantPosition(nodes.Get(6), 0, 120);
    ns3::AnimationInterface::SetConstantPosition(nodes.Get(7), 0, 140);
    ns3::AnimationInterface::SetConstantPosition(nodes.Get(8), 0, 160);
    ns3::AnimationInterface::SetConstantPosition(nodes.Get(9), 10, 10);
    ns3::AnimationInterface::SetConstantPosition(nodes.Get(10), 15, 10);
    ns3::AnimationInterface::SetConstantPosition(nodes.Get(11), 20, 10);

    Simulator::Run();
    Simulator::Destroy();
    return 0;
}