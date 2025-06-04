using PacketDotNet;
using SharpPcap;
using SharpPcap.LibPcap;
using System.Net;
using System.Net.NetworkInformation;
using System.Net.Sockets;
using Spectre.Console;

namespace ConsoleClient
{
	public class Program
	{
		private static int packetCount = 0; // Counter for captured packets
		private static bool stopCapture = false; // Flag to stop capturing
		private static Table packetTable;
		private static readonly int maxRows = 20; // Clearr table after 20 packets

		static void Main(string[] args)
		{
			Console.WriteLine("Packet Sniffer: Setting up SharpPcap...");


			try
			{
				// Initialize table
				packetTable = new Table()
					.AddColumn("Packet #")
					.AddColumn("Timestamp")
					.AddColumn("Src MAC")
					.AddColumn("Dst MAC")
					.AddColumn("Src IP")
					.AddColumn("Dst IP")
					.AddColumn("Protocol")
					.AddColumn("Transport Details");



				// Get all network interfaces that can be used for packet capture
				var devices = CaptureDeviceList.Instance;

				if (devices.Count == 0)
				{
					Console.WriteLine("No network interfaces found.");
					return;
				}

				// Get system network interfaces for IP address
				var systemInterfaces = NetworkInterface.GetAllNetworkInterfaces();

				// List available interfaces
				Console.WriteLine("Available network interfaces:");
				for (int i = 0; i < devices.Count; i++)
				{
					var device = devices[i];
					// Extract ID from device name
					var deviceId = device.Name.Split("_").Last();

					// Take the first matching system interface by ID
					var systemInterface = systemInterfaces.FirstOrDefault(si => si.Id == deviceId);

					// Get IPv4 address if available
					var ipAddress = systemInterface?.GetIPProperties().UnicastAddresses
						.FirstOrDefault(a => a.Address.AddressFamily == AddressFamily.InterNetwork)?.Address;

					Console.WriteLine($"[{i}] {device.Name} ({device.Description})");
					Console.WriteLine($"  IP: {(ipAddress != null ? ipAddress.ToString() : "No IPv4 address")}");
					Console.WriteLine($"  MAC: {(device.MacAddress != null ? device.MacAddress.ToString() : "No MAC address")}");
				}

				// Prompt user to select an interface
				Console.WriteLine("\nEnter the index of the interface to use (e.g., 0, 1, ...):");
				string? input = Console.ReadLine();
				if (!int.TryParse(input, out int index) || index < 0 || index >= devices.Count)
				{
					Console.WriteLine("Invalid index. Please run again and enter a valid number.");
					return;
				}

				// Prompt user for BPF filter
				Console.WriteLine("\nEnter a BPF filter (e.g., 'tcp port 80', 'udp', 'icmp and src 192.168.1.48') or press Enter for none:");
				Console.WriteLine("Examples: 'tcp port 80 (HTTP), 'udp port 53' (DNS), 'ip proto 1' (ICMP)");
				string? bpfFilter = Console.ReadLine()?.Trim();
				if (string.IsNullOrEmpty(bpfFilter))
				{
					bpfFilter = ""; // No filter, capture all packets
				}

				// Select the device based on user input
				// We need to cast because not all ICaptureDevice can be used for live capture
				var selectedDevice = devices[index] as LibPcapLiveDevice; // Cast to LibPcapLiveDevice for packet capture
				if (selectedDevice == null)
				{
					Console.WriteLine("Selected device is not a live capture device.");
					return;
				}

				// Open in promiscuous mode, 65536 max packet size, 1000ms timeout
				selectedDevice.Open(DeviceModes.Promiscuous, 1000);

				// Set the BPF filter if provided
				if (!string.IsNullOrEmpty(bpfFilter))
				{
					try
					{
						selectedDevice.Filter = bpfFilter; // Set the BPF filter
						Console.WriteLine($"Filter applied: {bpfFilter}");
					}
					catch (Exception ex)
					{
						Console.WriteLine($"Failed to set filter: {ex.Message}");
						selectedDevice.Close();
						return;
					} 
				}
				else
				{
					Console.WriteLine("No filter applied, capturing all packets.");
				}

				Console.WriteLine($"Opened: {selectedDevice.Description} ({selectedDevice.Name})");
				Console.WriteLine("Capturing packets... Press 'Q' to stop.");

				// Register packet arrival handler
				// This executes when a packet is captured by the device more efficient than polling the device
				// This will run in the new thread we created below since the .Capture() method is assigned in the new thread
				selectedDevice.OnPacketArrival += Device_OnPacketArrival;

				// Start capture in a aseparate thread so we can handle user input concurrently
				Thread captureThread = new Thread(() => selectedDevice.Capture());
				captureThread.Start();

				// Display table and check for 'Q' key to stop capture
				AnsiConsole.Live(packetTable)
					.Start(ctx =>
					{
						while (!stopCapture)
						{
							if (Console.KeyAvailable)
							{
								var key = Console.ReadKey(true).KeyChar;
								if (char.ToUpper(key) == 'Q')
								{
									stopCapture = true;
									selectedDevice.StopCapture();
									Console.WriteLine("\nCapture stopped.");
								}
							}
							ctx.Refresh(); // Refresh the table display
							Thread.Sleep(100); // Prevent CPU overuse
						}
					});


				// Wait for capture thread to finish
				captureThread.Join();

				// Close the device
				selectedDevice.Close();
				Console.WriteLine("\nDevice closed. Press any key to exit...");
				Console.ReadKey();

			}
			catch (Exception ex)
			{
				Console.WriteLine($"Error setting up SharpPcap: {ex.Message}");
				Console.WriteLine("Ensure Npcap is installed.");
			}
		}

		private static void Device_OnPacketArrival(object sender, PacketCapture e)
		{
			if (stopCapture)
			{
				return;
			}

			// Convert PacketCapture to RawCapture so we can access the raw packet data
			var rawPacket = e.GetPacket();
			packetCount++;

			// Clear table if too many rows
			lock (packetTable)
			{
				if (packetTable.Rows.Count >= maxRows)
				{
					packetTable.Rows.Clear();
				}
			}


			// Parse the packet with PacketDotNet
			var parsedPacket = Packet.ParsePacket(rawPacket.LinkLayerType, rawPacket.Data);
			if (parsedPacket is EthernetPacket ethernetPacket)
			{
				string srcMac = ethernetPacket.SourceHardwareAddress.ToString();
				string dstMac = ethernetPacket.DestinationHardwareAddress.ToString();

				// Check for IPv4 payload
				if (ethernetPacket.PayloadPacket is IPPacket ipPacket && ipPacket.Version == IPVersion.IPv4)
				{
					string srcIp = ipPacket.SourceAddress.ToString();
					string dstIp = ipPacket.DestinationAddress.ToString();
					string protocol = ipPacket.Protocol.ToString();
					string transportDetails = string.Empty;

					// Parse transport layer based on protocol
					if (ipPacket.PayloadPacket is TcpPacket tcpPacket)
					{
						transportDetails = $"Ports: {tcpPacket.SourcePort}->{tcpPacket.DestinationPort}, Flags: {(tcpPacket.Synchronize ? "SYN " : "")}" +
							$"{(tcpPacket.Acknowledgment ? "ACK " : "")}{(tcpPacket.Finished ? "FIN " : "")}".Trim();
					}
					else if (ipPacket.PayloadPacket is UdpPacket udpPacket)
					{
						transportDetails = $"Ports: {udpPacket.SourcePort}->{udpPacket.DestinationPort}";
					}
					else if (ipPacket.PayloadPacket is IcmpV4Packet icmpPacket)
					{
						transportDetails = $"Type Code: {icmpPacket.TypeCode}";
					}
					else
					{
						transportDetails = $"Unexpected: {ipPacket.Protocol}";
					}

					// Add row to table
					lock (packetTable)
					{
						packetTable.AddRow(
							packetCount.ToString(),
							rawPacket.Timeval.Date.ToString("HH:mm:ss.fff"),
							srcMac,
							dstMac,
							srcIp,
							dstIp,
							protocol,
							transportDetails
						);
					}

				}
				else
				{
					// Add row for non-IPv4 packet
					lock (packetTable)
					{
						packetTable.AddRow(
							packetCount.ToString(),
							rawPacket.Timeval.Date.ToString("HH:mm:ss.fff"),
							srcMac,
							dstMac,
							"-",
							"-",
							"-",
							"Non-IPv4 Packet"
							);
					}
				}
			}
			else
			{
				// Add row for non-Ethernet packet
				lock (packetTable)
				{
					packetTable.AddRow(
						packetCount.ToString(),
						rawPacket.Timeval.Date.ToString("HH:mm:ss.fff"),
						"-",
						"-",
						"-",
						"-",
						"-",
						"Non-Ethernet Packet"
					);
				}
			}
		}
	}
}
