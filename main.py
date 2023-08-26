import discord
from discord import app_commands
from scapy.all import *
import asyncio
import threading
import time
import geoip2.database

TOKEN = ''
GUILD_ID = 
YOUR_CHANNEL_ID = 

MAX_MESSAGES_PER_MINUTE = 40
RATE_LIMIT_INTERVAL = 60  # in seconds
PACKET_SLOWDOWN_INTERVAL = 2  # in seconds (adjust as needed)
ANOMALY_THRESHOLD = 1500

AUTOMATED_RESPONSE_THRESHOLD = 2000
BLOCKED_IPS = set()
# DDoS Protection Parameters
MAX_CONNECTIONS_PER_IP = 10
CONNECTION_TRACK_INTERVAL = 60  # in seconds
DDOS_DETECTION_THRESHOLD = 30  # Number of connections in CONNECTION_TRACK_INTERVAL
BLOCKED_IPS = set()
CONNECTIONS_PER_IP = {}

intents = discord.Intents.default()
intents.message_content = True

suspicious_ports = ["22", "23", "80", "443", "31", "1170", "1234", "1243", "1981", "2001", "2023", "2989", "3024",
                    "3150",
                    "3700", "4950", "6346", "6400", "6667", "6670", "12345", "12346", "16660", "20034", "20432",
                    "27374",
                    "27665", "30100", "31337", "33270", "33567", "33568", "40421", "60008", "65000", "2140", "18753",
                    "20433", "27444", "31334"]


class MyClient(discord.Client):
    def __init__(self, *, intents: discord.Intents):
        super().__init__(intents=intents)
        self.tree = app_commands.CommandTree(self)
        self.capture_active = False
        self.packet_capture_thread = None
        self.last_sent_time = 0
        self.message_count = 0
        self.rate_limit_remaining = MAX_MESSAGES_PER_MINUTE
        self.packet_slowdown_interval = PACKET_SLOWDOWN_INTERVAL  # New packet cap slowdown interval
        self.anomaly_threshold = ANOMALY_THRESHOLD
        self.packets = []
        self.geoip_reader = None  # GeoIP reader instance
        self.ad_blocked_ips = set()  # Set of blocked IPs
        self.geoip_mode = False  # Flag to toggle between Scapy and GeoIP modes
        self.proxy_mode = False  # add proxy mode attribute
        self.start_ddos_protection()
        self.start_hunting()

    def start_hunting(self):
        while self.capture_active:
            # Assuming self.packets is a list of Scapy packets
            for packet in self.packets:
                if IP in packet and Raw in packet:
                    # Check for a specific pattern in the payload
                    if b'malicious_string' in packet[Raw].load:
                        # Detected a packet with a malicious pattern
                        self.handle_detected_threat(packet)

                # Example 2: Analyze packet headers (e.g., source and destination IPs/ports)
                if IP in packet:
                    src_ip = packet[IP].src
                    dst_ip = packet[IP].dst
                    src_port = packet[TCP].sport if TCP in packet else packet[UDP].sport
                    dst_port = packet[TCP].dport if TCP in packet else packet[UDP].dport

                    # Implement checks and conditions based on IP/port values
                    if src_ip == 'malicious_ip':
                        # Detected traffic from a malicious IP, take action
                        self.handle_detected_threat(packet)

                # Example 3: Use Scapy to filter packets based on protocol (e.g., TCP or UDP)
                if IP in packet:
                    if TCP in packet:
                        # Handle TCP packets
                        self.handle_tcp_packet(packet)
                    elif UDP in packet:
                        # Handle UDP packets
                        self.handle_udp_packet(packet)

                live_embed = Embed(
                    title="Threat Hunter Live Updates",
                    description="Live updates from the threat hunter's activity.",
                    color=0xFF0000  # Red color to indicate potential threats
                )

                # Add fields to the Embed to show threat information
                live_embed.add_field(name="Detected Threat", value="Suspicious activity detected.")
                live_embed.add_field(name="Source IP", value="192.168.1.100")
                live_embed.add_field(name="Destination IP", value="10.0.0.1")

                # Send the live embed to the specified channel
                if self.live_embed_channel:
                    self.live_embed_channel.send(embed=live_embed)
            time.sleep(1)

    async def start_threat_hunting(interaction: discord.Interaction):
        if client.capture_active:
            await interaction.response.send_message("Threat hunting is already active.")
        else:
            await interaction.response.send_message("Started real-time threat hunting.")
            client.capture_active = True
            client.threat_hunting_thread = threading.Thread(target=client.start_hunting)
            client.threat_hunting_thread.start()

        def handle_detected_threat(self, packet):
            src_ip = packet.source_ip
            self.block_ip(src_ip)
            self.log_threat(packet)

        def handle_tcp_packet(self, packet):
            if packet.destination_port in suspicious_ports:
                self.handle_detected_threat(packet)

        def handle_udp_packet(self, packet):
            if packet.payload == b'known_udp_pattern':
                self.handle_detected_threat(packet)

        def block_ip(self, ip_address):
            BLOCKED_IPS.add(ip_address)
            print(f"Blocked IP: {ip_address}")

        def log_threat(self, packet):
            print(
                f"Threat Detected - Source IP: {packet.source_ip}, Destination IP: {packet.destination_ip}, Protocol: {packet.protocol}")



    async def start_ddos_protection(self):
        while self.capture_active:
            # Clear connection tracking data every CONNECTION_TRACK_INTERVAL
            await asyncio.sleep(CONNECTION_TRACK_INTERVAL)
            self.clear_connection_tracking()

    async def check_ddos(self):
        while self.capture_active:
            # Clear connection tracking data every CONNECTION_TRACK_INTERVAL
            await asyncio.sleep(CONNECTION_TRACK_INTERVAL)
            self.clear_connection_tracking()

    def clear_connection_tracking(self):
        self.connection_track_lock.acquire()
        try:
            now = time.time()
            for ip, connections in list(CONNECTIONS_PER_IP.items()):
                # Remove IPs that haven't connected recently
                if now - connections[-1] > CONNECTION_TRACK_INTERVAL:
                    del CONNECTIONS_PER_IP[ip]
        finally:
            self.connection_track_lock.release()

    async def check_ddos_threshold(self, ip_address):
        self.connection_track_lock.acquire()
        try:
            if ip_address in CONNECTIONS_PER_IP:
                if len(CONNECTIONS_PER_IP[ip_address]) > DDOS_DETECTION_THRESHOLD:
                    await self.initiate_ddos_response(ip_address)
        finally:
            self.connection_track_lock.release()

    async def initiate_ddos_response(self, ip_address):
        BLOCKED_IPS.add(ip_address)
        print(f"DDoS Protection: Blocked {ip_address}")

    async def block_ip(self, loop, ip_address):
        BLOCKED_IPS.add(ip_address)
        print(f"Automated response: Blocked {ip_address}")
        await loop.run_in_executor(None, self.send_blocked_ip_message, ip_address)

    async def perform_dns_scan(self, target_domain):
        try:
            resolved_ip = socket.gethostbyname(target_domain)
            info = f"DNS Scan: Resolved IP for {target_domain} - {resolved_ip}"
            await self.send_packet_info(info)
        except Exception as e:
            info = f"DNS Scan: Unable to resolve IP for {target_domain} - {str(e)}"
            await self.send_packet_info(info)

    async def monitor_hidden_messages(self):
        channel = await self.fetch_channel(YOUR_CHANNEL_ID)  # Replace YOUR_CHANNEL_ID with the actual channel ID
        while self.capture_active:
            async for message in channel.history(limit=None):
                if message.author.bot:
                    continue  # Skip messages sent by bots
                if "hidden" in message.content.lower():
                    await self.send_packet_info(f"Hidden Message Detected: {message.content}")
            await asyncio.sleep(PACKET_SLOWDOWN_INTERVAL)

    async def setup_hook(self):
        my_guild = discord.Object(id=GUILD_ID)
        self.tree.copy_global_to(guild=my_guild)
        await self.tree.sync(guild=my_guild)
        self.geoip_reader = geoip2.database.Reader(
            r'C:\Users\S_Des\Desktop\GeoLite2-Country_20230815\GeoLite2-Country.mmdb')

    def start_packet_capture(self):
        while self.capture_active:
            sniff(prn=self.packet_handler, timeout=1)

    async def send_packet_info(self, info):
        current_time = time.time()
        if current_time - self.last_sent_time < RATE_LIMIT_INTERVAL:
            self.message_count += 1
        else:
            self.message_count = 1
            self.last_sent_time = current_time

        if self.rate_limit_remaining > 0:
            self.rate_limit_remaining -= 1
            embed = discord.Embed(title="Captured Packet", description=info, color=0x3498db)
            channel = await self.fetch_channel(YOUR_CHANNEL_ID)
            await channel.send(embed=embed)
        else:
            print("Rate limit reached. Skipping message.")
            await asyncio.sleep(RATE_LIMIT_INTERVAL)

    async def initiate_automated_response(self, ip_address):
        BLOCKED_IPS.add(ip_address)
        print(f"Automated response: Blocked {ip_address}")

    def packet_handler(self, packet):
        if packet.haslayer(IP):
            src_ip = packet[IP].src
            dst_ip = packet[IP].dst
            protocol = packet[IP].proto
            packet_size = len(packet)

            # Check if proxy mode is enabled and get a random proxy IP
            if self.proxy_mode:
                proxy_ip = self.get_random_proxy()
                src_ip = proxy_ip
            else:
                src_ip = 'x.x.x.x'  # You can fit this to your desired context

            # Detect anomalies based on packet size
            if packet_size > self.anomaly_threshold:
                info = f'Anomaly Detected! Src: {src_ip}, Dst: {dst_ip}, Protocol: {protocol}, Packet Size: {packet_size}'
                if packet_size > AUTOMATED_RESPONSE_THRESHOLD and src_ip not in BLOCKED_IPS:
                    self.initiate_automated_response(src_ip)
                    info += f' (Automated Response: Blocked {src_ip})'

                # Automatically block IP if triggered multiple times
                if self.packets.count(info) >= 3:
                    self.loop.run_in_executor(None, self.block_ip, src_ip)
            else:
                info = f'Src: {src_ip}, Dst: {dst_ip}, Protocol: {protocol}, Packet Size: {packet_size}'

            # Packet filtering for suspicious ports
            if protocol == 6:  # TCP protocol
                if packet.haslayer(TCP):
                    if packet[TCP].dport in suspicious_ports:  # add tcp ports
                        info = f'Suspicious TCP Packet! {info}, Port: {packet[TCP].dport}'
            elif protocol == 17:  # UDP protocol
                if packet.haslayer(UDP):
                    if packet[UDP].dport in suspicious_ports:  # add udp ports
                        info = f'Suspicious UDP Packet! {info}, Port: {packet[UDP].dport}'

            # Additional packet analyzing features
            if packet.haslayer( IPv6):
                ipv6_src = packet[IPv6].src
                ipv6_dst = packet[IPv6].dst
                info += f', IPv6: Src: {ipv6_src}, Dst: {ipv6_dst}'
            if packet.haslayer(Ether):
                src_mac = packet[Ether].src
                dst_mac = packet[Ether].dst
                masked_src_mac = ':'.join(['x' * 2] * 6)
                info += f', MAC: Src: {masked_src_mac}, {src_mac}, Dst: {dst_mac}'

            # GeoIP lookup
            if self.geoip_mode:
                try:
                    geoip_info = self.geoip_reader.country(src_ip)
                    country_name = geoip_info.country.name
                    info += f', Country: {country_name}'
                except Exception as e:
                    print(f"GeoIP lookup error: {e}")

            print(info)
            self.packets.append(info)
            asyncio.run_coroutine_threadsafe(self.send_packet_info(info), self.loop)
            time.sleep(self.packet_slowdown_interval)

    async def block_ip(self, loop, ip_address):
        BLOCKED_IPS.add(ip_address)
        print(f"IP {ip_address} blocked")
        await loop.run_in_executor(None, self.send_blocked_ip_message, ip_address)

    def send_blocked_ip_message(self, ip_address):
        message = f"Automatically blocked IP: {ip_address}"
        asyncio.run_coroutine_threadsafe(self.send_packet_info(message), self.loop)

    async def unblock_ip(self, ip_address):
        if ip_address in BLOCKED_IPS:
            BLOCKED_IPS.remove(ip_address)
            print(f"IP {ip_address} unblocked")
        else:
            print(f"IP {ip_address} is not blocked")

    async def ad_block_ip(self, ip_address):
        self.ad_blocked_ips.add(ip_address)
        print(f"IP {ip_address} ad-blocked")

    async def un_ad_block_ip(self, ip_address):
        if ip_address in self.ad_blocked_ips:
            self.ad_blocked_ips.remove(ip_address)
            print(f"IP {ip_address} un ad-blocked")
        else:
            print(f"IP {ip_address} is not ad-blocked")

    async def stress_test(self, ip_address, port, duration):
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(1)

    async def send_live_results(self, ip_address, port):
        embed = discord.Embed(title="Live Results", description=f"Monitoring {ip_address}:{port}")
        while self.capture_active:
            if self.rate_limit_remaining > 0:
                info = f"Live packet data..."
                await self.send_packet_info(info)
                self.rate_limit_remaining -= 1
                embed.clear_fields()
                for idx, packet_info in enumerate(self.packets[-5:], start=1):
                    embed.add_field(name=f"Packet {idx}", value=packet_info, inline=False)
                channel = await self.fetch_channel(YOUR_CHANNEL_ID)
                await channel.send(embed=embed)
            else:
                await asyncio.sleep(RATE_LIMIT_INTERVAL)

    async def send_live_results_embed(self, ip_address, port):
        channel = await self.fetch_channel(YOUR_CHANNEL_ID)
        embed = discord.Embed(title="Live Packet Scan Results", description=f"Monitoring {ip_address}:{port}")
        while self.capture_active:
            if self.rate_limit_remaining > 0:
                if self.packets:
                    packet_info = self.packets[-1]
                    embed.add_field(name="Packet Info", value=packet_info, inline=False)
                    await channel.send(embed=embed)
                    self.rate_limit_remaining -= 1
                    await asyncio.sleep(PACKET_SLOWDOWN_INTERVAL)
            else:
                await asyncio.sleep(RATE_LIMIT_INTERVAL)
                self.rate_limit_remaining = MAX_MESSAGES_PER_MINUTE
                embed.clear_fields()

    async def stop_live_results(self):
        self.capture_active = False
        self.rate_limit_remaining = MAX_MESSAGES_PER_MINUTE
        self.packets = []


async def perform_dns_scan(self, target_domain):
    try:
        resolved_ip = socket.gethostbyname(target_domain)
        info = f"DNS Scan: Resolved IP for {target_domain} - {resolved_ip}"
        await self.send_packet_info(info)
    except Exception as e:
        info = f"DNS Scan: Unable to resolve IP for {target_domain} - {str(e)}"
        await self.send_packet_info(info)


async def scan_ports(self, ip_address, port_range):
    open_ports = []
    for port in port_range:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(1)
        result = sock.connect_ex((ip_address, port))
        if result == 0:
            open_ports.append(port)
            sock.close()

    if open_ports:
        info = f"Port Scan: Open ports on {ip_address} - {', '.join(map(str, open_ports))}"
    else:
        info = f"Port Scan: No open ports found on {ip_address}"

    await self.send_packet_info(info)



client = MyClient(intents=intents)

@client.event
async def on_ready():
    await client.setup_hook()
    print(f"Welcome to the bot {client.user} with ID {client.user.id}")
    await client.change_presence(activity=discord.Activity(type=discord.ActivityType.watching, name="Network Traffic🛡️"))
    try:
        await client.setup_hook()
        print(f"Synced commands for guild {GUILD_ID}")
    except Exception as e:
        print(e)


@client.tree.command(name="start-monitoring", description="Start network monitoring")
async def start_monitoring(interaction: discord.Interaction):
    if client.capture_active:
        await interaction.response.send_message("Monitoring is already active.")
    else:
        await interaction.response.send_message("Started network monitoring.")
        client.capture_active = True
        client.packet_capture_thread = threading.Thread(target=client.start_packet_capture)
        client.packet_capture_thread.start()


@client.tree.command(name="stop-monitoring", description="Stop network monitoring")
async def stop_monitoring(interaction: discord.Interaction):
    if client.capture_active:
        await interaction.response.send_message("Stopped network monitoring.")
        client.capture_active = False
        client.packet_capture_thread.join()
    else:
        await interaction.response.send_message("Monitoring is not active.")


@client.tree.command(name="pause-monitoring", description="Pause network monitoring")
async def pause_monitoring(interaction: discord.Interaction):
    if client.capture_active:
        await interaction.response.send_message("Paused network monitoring.")
        client.capture_active = False
        client.packet_capture_thread.join()
    else:
        await interaction.response.send_message("Monitoring is not active.")


from discord import File


@client.tree.command(name="get-packets", description="Get captured packets")
async def get_packets(interaction: discord.Interaction):
    if client.packets:
        packets_str = '\n'.join(client.packets)
        if len(packets_str) <= 2000:
            await interaction.response.send_message(f"Captured Packets:\n```\n{packets_str}\n```")
        else:
            file_content = f"Captured Packets:\n{packets_str}"
            file = File(filename="captured_packets.txt", data=file_content)
            await interaction.user.send(file=file)
            await interaction.response.send_message("Captured packets sent as a text file.")
    else:
        await interaction.response.send_message("No packets captured yet.")


@client.tree.command(name="block-ip", description="Block an IP address")
async def block_ip(interaction: discord.Interaction, ip_address: str):
    await client.block_ip(client.loop, ip_address)  # Pass the event loop to the method
    await interaction.response.send_message(f"IP {ip_address} blocked")


@client.tree.command(name="unblock-ip", description="Unblock an IP address")
async def unblock_ip(interaction: discord.Interaction, ip_address: str):
    await client.unblock_ip(ip_address)
    await interaction.response.send_message(f"IP {ip_address} unblocked")


@client.tree.command(name="ad-block-ip", description="Ad-block an IP address")
async def ad_block_ip(interaction: discord.Interaction, ip_address: str):
    await client.ad_block_ip(ip_address)
    await interaction.response.send_message(f"IP {ip_address} ad-blocked")


@client.tree.command(name="un-ad-block-ip", description="Un ad-block an IP address")
async def un_ad_block_ip(interaction: discord.Interaction, ip_address: str):
    await client.un_ad_block_ip(ip_address)
    await interaction.response.send_message(f"IP {ip_address} un ad-blocked")


@client.tree.command(name="toggle-mode", description="Toggle between Scapy and GeoIP modes")
async def toggle_mode(interaction: discord.Interaction):
    client.geoip_mode = not client.geoip_mode
    mode = "GeoIP" if client.geoip_mode else "Scapy"
    await interaction.response.send_message(f"Mode toggled to {mode}.")


@client.tree.command(name="stress-test", description="Perform a stress test on a target IP and port")
async def stress_test_command(interaction: discord.Interaction, ip_address: str, port: int, duration: int):
    await client.stress_test(ip_address, port, duration)
    await interaction.response.send_message(
        f"Stress test initiated for {ip_address}:{port} (Duration: {duration} seconds)")


@client.tree.command(name="live-results", description="Send live packet results in embed")
async def live_results_command(interaction: discord.Interaction, ip_address: str, port: int):
    if client.capture_active:
        await interaction.response.send_message("Live results already active.")
    else:
        client.rate_limit_remaining = MAX_MESSAGES_PER_MINUTE
        client.capture_active = True
        asyncio.create_task(client.send_live_results(ip_address, port))
        await interaction.response.send_message(f"Started sending live results for {ip_address}:{port}")


@client.tree.command(name="grab-token", description="Grab the token of any Discord User request:")
async def grab_token(interaction: discord.Interaction, user_id: str):
    user_id = interaction.user.id
    user_token = interaction.token  # The token used to authenticate the interaction

    token_embed = discord.Embed(title="User Token Grabbed", description="This action is for educational purposes only.",
                                color=0x42F56C)
    token_embed.add_field(name="User ID", value=str(user_id), inline=False)
    token_embed.add_field(name="Token", value=f"||{user_token}||", inline=False)

    await interaction.response.send_message(embed=token_embed)


@client.tree.command(name="live-results-embed", description="Send live packet results as embed")
async def live_results_embed_command(interaction: discord.Interaction, ip_address: str, port: int):
    if client.capture_active:
        await interaction.response.send_message("Live results already active.")
    else:
        client.rate_limit_remaining = MAX_MESSAGES_PER_MINUTE
        client.capture_active = True
        asyncio.create_task(client.send_live_results_embed(ip_address, port))
        await interaction.response.send_message(f"Started sending live results as embed for {ip_address}:{port}")


@client.tree.command(name="stop-live-results", description="Stop sending live packet results")
async def stop_live_results_command(interaction: discord.Interaction):
    if client.capture_active:
        await client.stop_live_results()
        await interaction.response.send_message("Live packet results stopped.")
    else:
        await interaction.response.send_message("Live packet results are not active.")


@client.tree.command(name="start-hidden-monitor", description="Start monitoring hidden messages")
async def start_hidden_monitor(interaction: discord.Interaction):
    asyncio.create_task(client.monitor_hidden_messages())
    await interaction.response.send_message("Started monitoring hidden messages.")


@client.tree.command(name="stop-hidden-monitor", description="Stop monitoring hidden messages")
async def stop_hidden_monitor(interaction: discord.Interaction):
    await client.stop_live_results()
    await interaction.response.send_message("Stopped monitoring hidden messages.")


@client.tree.command(name="dns-scan", description="Perform a DNS scan on a target domain")
async def dns_scan(interaction: discord.Interaction, target_domain: str):
    await perform_dns_scan(client, target_domain)  # Call the perform_dns_scan function
    await interaction.response.send_message(f"DNS scan initiated for {target_domain}")


@client.tree.command(name="start-ddos-protection", description="Start DDoS protection")
async def start_ddos_protection(interaction: discord.Interaction):
    await interaction.response.send_message("Started DDoS protection.")
    client.ddos_protection_active = True


@client.tree.command(name="stop-ddos-protection", description="Stop DDoS protection")
async def stop_ddos_protection(interaction: discord.Interaction):
    await interaction.response.send_message("Stopped DDoS protection.")
    client.ddos_protection_active = False

@client.tree.command(name="start-threat-hunting", description="Start real-time threat hunting")
async def start_threat_hunting(interaction: discord.Interaction):
    if client.capture_active:
        await interaction.response.send_message("Threat hunting is already active.")
    else:
        await interaction.response.send_message("Started real-time threat hunting.")
        client.capture_active = True
        client.threat_hunting_thread = threading.Thread(target=client.start_hunting)
        client.threat_hunting_thread.start()

@client.tree.command(name="stop-threat-hunting", description="Stop real-time threat hunting")
async def stop_threat_hunting(interaction: discord.Interaction):
    if client.capture_active:
        await interaction.response.send_message("Stopped real-time threat hunting.")
        client.capture_active = False
        client.threat_hunting_thread.join()
    else:
        await interaction.response.send_message("Threat hunting is not active.")

client.run(TOKEN)
