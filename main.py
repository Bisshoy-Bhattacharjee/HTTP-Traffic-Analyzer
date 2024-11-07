import pyshark
import requests
from collections import defaultdict
import time


# Function to get the geographical location of an IP
def get_ip_location(ip_address):
    try:
        response = requests.get(f"http://ip-api.com/json/{ip_address}")
        data = response.json()
        if data['status'] == 'success':
            return {
                "country": data.get("country"),
                "region": data.get("regionName"),
                "city": data.get("city"),
                "latitude": data.get("lat"),
                "longitude": data.get("lon")
            }
    except requests.RequestException as e:
        print(f"Request failed: {e}")
    return None


# Initialize live capture for HTTPS traffic (port 443)
def capture_https_packets():
    capture = pyshark.LiveCapture(interface='Wi-Fi', display_filter='tcp.port == 443')
    ip_locations = defaultdict(dict)  # Dictionary to store IP locations

    try:
        print("Starting HTTPS live capture...\n")
        for packet in capture.sniff_continuously(packet_count=0):  # Adjust packet count as needed.Found 0 to be perfect
            # Check if the packet has IP layer
            if 'IP' in packet:
                ip_src = packet.ip.src
                ip_dst = packet.ip.dst

                # Retrieve and print location info for source IP
                if ip_src not in ip_locations:
                    ip_locations[ip_src] = get_ip_location(ip_src)
                    if ip_locations[ip_src]:
                        print(f"Source IP: {ip_src} - Location: {ip_locations[ip_src]['city']}, "
                              f"{ip_locations[ip_src]['region']}, {ip_locations[ip_src]['country']} "
                              f"({ip_locations[ip_src]['latitude']}, {ip_locations[ip_src]['longitude']})")
                    else:
                        print(f"Source IP: {ip_src} - Location: Not available")

                # Retrieve and print location info for destination IP
                if ip_dst not in ip_locations:
                    ip_locations[ip_dst] = get_ip_location(ip_dst)
                    if ip_locations[ip_dst]:
                        print(f"Destination IP: {ip_dst} - Location: {ip_locations[ip_dst]['city']}, "
                              f"{ip_locations[ip_dst]['region']}, {ip_locations[ip_dst]['country']} "
                              f"({ip_locations[ip_dst]['latitude']}, {ip_locations[ip_dst]['longitude']})")
                    else:
                        print(f"Destination IP: {ip_dst} - Location: Not available")

                time.sleep(0.1)  # Adding a slight delay to avoid rate-limiting by API

    except KeyboardInterrupt:
        print("\nCapture interrupted by user.")

    finally:
        capture.close()

# Run the capture function
capture_https_packets()
