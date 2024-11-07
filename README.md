# HTTP-Traffic-Analyzer
A Python-based tool for analyzing HTTP traffic using Wireshark and Python. This project helps you capture, filter, and analyze network traffic to monitor HTTP requests and responses in real-time.

Features
Captures HTTP packets from network traffic.
Filters HTTP packets to display relevant details like request methods, URLs, and response codes.
Provides a user-friendly output for analysis.
Requirements
To run this tool, you need the following:

Wireshark: Ensure Wireshark is installed on your machine to capture live network traffic.
Python 3.x: The tool is developed with Python 3.x.
Python Libraries:
pyshark: A Python wrapper for Wireshark to process packet capture files.
scapy: For additional packet manipulation and analysis.
Install the required libraries using the following command:

Usage
Start Capturing HTTP Traffic
Run the http_traffic_analyzer.py script to start capturing HTTP packets from the network:

You can customize the script’s behavior by adjusting the following parameters in the script:

Packet capture interface: Specify the network interface to capture packets from.
Capture filter: Set the filter for packet types (e.g., http for HTTP traffic).

Contributing
Feel free to fork this repository and contribute by submitting pull requests. If you find bugs or have feature requests, please open an issue.
