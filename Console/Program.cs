using PacketDotNet;
using SharpPcap;
using SharpPcap.LibPcap;
using System.Net;
using System.Net.NetworkInformation;
using System.Net.Sockets;

namespace ConsoleClient
{
	public class Program
	{
		private static int packetCount = 0; // Counter for captured packets
		private static readonly int maxPackets = 10; // Maximum packets to capture
		private static bool stopCapture = false; // Flag to stop capturing
		static void Main(string[] args)
		{
			Console.WriteLine("Packet Sniffer: Setting up SharpPcap...");


			try
			{
				// Get all network interfaces
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
				string input = Console.ReadLine();
				if (!int.TryParse(input, out int index) || index < 0 || index >= devices.Count)
				{
					Console.WriteLine("Invalid index. Please run again and enter a valid number.");
					return;
				}

				// Select the device based on user input
				var selectedDevice = devices[index] as LibPcapLiveDevice; // Cast to LibPcapLiveDevice for packet capture
				if (selectedDevice == null)
				{
					Console.WriteLine("Selected device is not a live capture device.");
					return;
				}

				// Open in promiscuous mode, 65536 max packet size, 1000ms timeout
				selectedDevice.Open(DeviceModes.Promiscuous, 1000);
				Console.WriteLine($"Opened: {selectedDevice.Description} ({selectedDevice.Name})");
				Console.WriteLine("Capturing packets... PPress 'Q' to stop (max 10 packets).");

				// Register packet arrival handler
				// This executes when a packet is captured by the device more efficient than polling
				selectedDevice.OnPacketArrival += Device_OnPacketArrival;

				// Start capture in a aseparate thread so we can handle user input concurrently
				Thread captureThread = new Thread(() => selectedDevice.Capture());
				captureThread.Start();

				// Check for 'Q' key to stop capture
				while (!stopCapture)
				{
					if (Console.KeyAvailable)
					{
						var key = Console.ReadKey(true).KeyChar;
						if (char.ToUpper(key) == 'Q')
						{
							stopCapture = true;
							selectedDevice.StopCapture();
						}
					}
					Thread.Sleep(100); // Prevent CPU overuse
				}

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
			if (stopCapture || packetCount >= maxPackets)
			{
				if (sender is LibPcapLiveDevice device)
				{
					device.StopCapture();
				}
				return;
			}

			// Convert PacketCapture to RawCapture
			var rawPacket = e.GetPacket();
			packetCount++;

			Console.WriteLine($"\nPacket #{packetCount}:");
			Console.WriteLine($"Timestamp: {rawPacket.Timeval.Date}");
			Console.WriteLine($"Length: {rawPacket.Data.Length} bytes");

			// Parse the packet with PacketDotNet
			var parsedPacket = Packet.ParsePacket(rawPacket.LinkLayerType, rawPacket.Data);
			if (parsedPacket is EthernetPacket ethernetPacket)
			{
				Console.WriteLine("Ethernet Header:");
				Console.WriteLine($"  Source MAC: {ethernetPacket.SourceHardwareAddress}");
				Console.WriteLine($"  Destination MAC: {ethernetPacket.DestinationHardwareAddress}");
				Console.WriteLine($"  EtherType: {ethernetPacket.Type}");

				// Check for IPv4 payload
				if (ethernetPacket.PayloadPacket is IPPacket ipPacket && ipPacket.Version == IPVersion.IPv4)
				{
					Console.WriteLine("IPv4 Header:");
					Console.WriteLine($"  Source IP: {ipPacket.SourceAddress}");
					Console.WriteLine($"  Destination IP: {ipPacket.DestinationAddress}");
					Console.WriteLine($"  Protocol: {ipPacket.Protocol}");
				}
				else
				{
					Console.WriteLine("Not an IPv4 packet (e.g., IPv6, ARP).");
				}
			}
			else
			{
				Console.WriteLine("Not an thernet packet.");
			}
		}
	}
}
