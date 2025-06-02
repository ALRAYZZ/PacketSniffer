using SharpPcap;
using System.Net;
using System.Net.NetworkInformation;
using System.Net.Sockets;

namespace ConsoleClient
{
	public class Program
	{
		static void Main(string[] args)
		{
			Console.WriteLine("Creating raw socket...");


			try
			{
				// Get all network interfaces
				var devices = CaptureDeviceList.Instance;

				if (!devices.Any())
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
					// Find matching system interface by name or ID
					var systemInterface = systemInterfaces.FirstOrDefault(si => device.Name.Contains(si.Id) ||
						device.Name.Contains(device.Name.Split("_").Last()));

					// Get IPv4 address if available
					var ipAddress = systemInterface?.GetIPProperties().UnicastAddresses
						.FirstOrDefault(a => a.Address.AddressFamily == System.Net.Sockets.AddressFamily.InterNetwork)?.Address;

					Console.WriteLine($"[{i}] {device.Name} ({device.Description})");
					Console.WriteLine($"  IP: {(ipAddress != null ? ipAddress.ToString() : "No IPv4 address")}");
					Console.WriteLine($"  MAC: {(device.MacAddress != null ? device.MacAddress.ToString() : "No MAC address")}");
				}
				Console.WriteLine("Setup complete.");
			}
			catch (Exception ex)
			{
				Console.WriteLine($"Failed to create raw socket: {ex.Message}");
			}
		}
	}
}
