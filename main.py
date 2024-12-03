import pyautogui
import time
import subprocess
import os
import pyshark
import shutil
from datetime import timezone
from collections import Counter
import datetime
import sys

channel_1 = "channel_1"
channel_2 = "channel_2"
server_name = "Relay_Server_1"
path_to_pf = "/etc/pf.conf"
global_timings = {}
blocking_status = "blocking"
is_mac = False

def reload_pf(path):
    try:
        # Run the command with sudo privileges
        subprocess.run(['sudo', 'pfctl', '-f', path], check=True)
        print("pfctl configuration reloaded successfully.")
    except subprocess.CalledProcessError as e:
        print(f"Command failed with error: {e}")
    except Exception as e:
        print(f"An unexpected error occurred: {e}")

def append_to_file(file_path, text):
    try:
        with open(file_path, 'a') as file:  # 'a' mode opens the file for appending
            file.write(text + '\n')  # Adds the text followed by a newline
        print(f"Text successfully appended to {file_path}")
    except Exception as e:
        print(f"An error occurred: {e}")

def block_ip(ip):
    """Block outbound UDP traffic to ip

    Arguments:
    ip - the IP address to block
    """
    # rule = f"FROOT Zoom IP Block {ip}"
    # os.system(f'sudo ufw deny out to {ip} proto udp')
    # print(f"Blocking IP {ip} now")
    # cmd = f'netsh advfirewall firewall add rule name="{rule}" dir=out action=block remoteip="{ip}" protocol=UDP'
    # os.system(cmd)
    if is_mac:
        append_to_file(f"{path_to_pf}", f"block drop quick on en0 proto udp to {ip}")
        reload_pf(path_to_pf)
    else:
        command = ['sudo', 'ufw', 'deny', 'in', 'from', ip, 'proto', 'udp']
        subprocess.run(command, check=True)
        command = ['sudo', 'ufw', 'deny', 'out', 'to', ip, 'proto', 'udp']
        subprocess.run(command, check=True)
        print(f"Successfully blocked incoming UDP traffic from {ip}")

    return

def capture_pcap(n, output='./pcap_files'):
    os.makedirs(output, exist_ok=True)

    # Define the command to run tcpdump
    command = None
    if not is_mac:
        command = ['timeout', '--signal=SIGKILL', '10', 'sudo', 'tcpdump', '(net 66.22.0.0/16 or net 162.0.0.0/8)', '-w', os.path.join(output, f'{n}.pcapng')]
    else:
        command = ['sudo', 'tcpdump', '(net 66.22.0.0/16 or net 162.0.0.0/8)', '-w', os.path.join(output, f'{n}.pcapng')]

    try:
        # Start the tcpdump process
        process = subprocess.Popen(command)
        # # Wait for 5 seconds
        time.sleep(5)
        
        # # Stop the tcpdump process
        if is_mac:
            process.terminate()
        
        # # os.killpg(os.getpgid(process.pid), signal.SIGINT)
        # process.terminate()
        # process.wait()

       # process.send_signal(signal.SIGINT)
        #process.terminate()
        process.wait()  # Ensure the process has terminated
        print("Capture completed")
        
    except subprocess.CalledProcessError as e:
        print(f"Error while running tcpdump: {e}")
    except KeyboardInterrupt:
        print("Capture stopped by user.")

def start_pcap(n, output='./pcap_files'):
    os.makedirs(output, exist_ok=True)
    command = None
    if not is_mac:
        command = ['timeout', '--signal=SIGKILL', '10', 'sudo', 'tcpdump', '(net 66.22.0.0/16 or net 162.0.0.0/8)', '-w', os.path.join(output, f'{n}.pcapng')]
    else:
        command = ['sudo', 'tcpdump', '-w', os.path.join(output, f'{n}.pcapng')]
    
    try:
        process = subprocess.Popen(command)
        return process
    except subprocess.CalledProcessError as e:
        print(f"Error while running tcpdump: {e}")
    except KeyboardInterrupt:
        print("Capture stopped by user.")

def stop_pcap(process):
    time.sleep(5)
    if is_mac and process:
        process.terminate()
    
    if process:
        process.wait()
    print("Capture completed")

def analyze_pcapng(n, output, tshark_path=None):
    """Open the pcap file for processing

    Arguments
    n - the trial number
    output - the pcap folder
    tshark_path - path to tshark binary (required for pyshark)
    """

    print(f"Start analyzing the {n}th pcapng file")

    # Construct the pcap file path
    save_dir = os.path.dirname(os.path.abspath(__file__))
    pcapng_file = os.path.join(save_dir, output, f"{n}.pcapng")

    # Check to see the pcap exists (it shoukd)
    if not os.path.exists(pcapng_file):
        print(f"Fatal: file {pcapng_file} does not exist")
        return
    
    # Open the packet capture and return
    cap = pyshark.FileCapture(pcapng_file, tshark_path=tshark_path, keep_packets=False)
    destinations = Counter()
    return cap, destinations

def process_pcap_analysis(cap: pyshark.FileCapture, destinations: Counter, i, output, blocking, start_time):
    """Process an open pcap file

    Arguments
    cap - The open pyshark file capture
    destinations - a Counter denoting the most common IP addresses
    i - The trial number


    This function loops through the pcap and records the UDP IP addresses collected during the experiment
    """
    found_first = 0
    found_tcp = 0
    found_udp = 0
    discord_media_time = None
    first_66_22_after_discord = None
    try:
        
        for packet in cap:
            if found_first == 0:
                found_first = float(packet.sniff_timestamp) # THE VERY FIRST PACKET
            if not discord_media_time and 'TLS' in packet:
                if hasattr(packet.tls, 'handshake_extensions_server_name'):
                    sni = packet.tls.handshake_extensions_server_name
                    # Check if '.discord.media' is in the SNI
                    if '.discord.media' in sni:
                        discord_media_time = float(packet.sniff_timestamp)
                        print(f"Found .discord.media in SNI at {discord_media_time}, Packet No: {packet.number}")
            if 0 == found_tcp and 'TCP' in packet and ".".join(packet.ip.dst.split(".")[:2]) in ["66.22"]: # ["206.247","144.195","134.224"]:
                found_tcp = float(packet.sniff_timestamp)
            if not first_66_22_after_discord and discord_media_time and 'IP' in packet and packet.ip.dst.startswith("66.22"):
                first_66_22_after_discord = float(packet.sniff_timestamp)
                print(f"First 66.22 packet found at {first_66_22_after_discord}")
            if 'IP' in packet and "UDP" in packet:
                # Media exchange packets have length 1044 so they're easy to fingerprint
                if 0 == found_udp:
                    found_udp = float(packet.sniff_timestamp)
                dst = packet.ip.dst
                dst = ".".join(packet.ip.dst.split(".")[:2])
                
                # Look at the known Discord IP prefixes
                if dst == "66.22":
                    destinations[packet.ip.dst] += 1
        time_diff = 5.0
        if discord_media_time and first_66_22_after_discord:
            time_diff = first_66_22_after_discord - discord_media_time
            print(f"Time difference between .discord.media and first 66.22: {time_diff} seconds")

        if destinations:

            # Pick the most common IPs out of the pcap
            most_common_dst = destinations.most_common(1)[0]
            print(f"\n The most common destination IP is:")
            print(f"  IP: {most_common_dst[0]}, show up times: {most_common_dst[1]}")
            all_media_ips = list(destinations.keys())

            # If we're blocking, block JUST the most common IP
            if blocking:
                block_ip(most_common_dst[0])
            
            print(f"Finish the {i+1}th iteration\n")

            # With the analysis done, write the results to the output CSV, includng the timestamp of the trial, the pcap file name, number of IPs, the recorded time to get to "Join Computer Audio", and...
            f = open(os.path.join(output,"results.csv"), "a")
            # print(f"{i+1},{datetime.datetime.now()},{i}.pcapng,{len(all_media_ips)},{global_timings[i]},{datetime.datetime.fromtimestamp(found_first,timezone.utc)},{datetime.datetime.fromtimestamp(found_tcp,timezone.utc)},{datetime.datetime.fromtimestamp(found_udp,timezone.utc)},{','.join(all_media_ips)}", file=f)
            print(f"{i+1},{datetime.datetime.now()},{i}.pcapng,{len(all_media_ips)},{datetime.datetime.fromtimestamp(found_first,timezone.utc)},{datetime.datetime.fromtimestamp(found_tcp,timezone.utc)},{datetime.datetime.fromtimestamp(found_udp,timezone.utc)},{time_diff},{most_common_dst[0]}", file=f)
            f.close()

            print(f"Finish the {i+1}th iteration\n")
        else:
            f = open(os.path.join(output,"results.csv"), "a")
            print("\n No destination IP found, please check the pcapng file")
            # print(f"{i+1},{datetime.datetime.now()},{i+1}.pcapng,0,{global_timings[i]},{datetime.datetime.fromtimestamp(found_first,timezone.utc)},{datetime.datetime.fromtimestamp(found_tcp,timezone.utc)},{datetime.datetime.fromtimestamp(found_udp,timezone.utc)}", file=f)
            print(f"{i+1},{datetime.datetime.now()},{i}.pcapng,0,{datetime.datetime.fromtimestamp(found_first,timezone.utc)},{datetime.datetime.fromtimestamp(found_tcp,timezone.utc)},{datetime.datetime.fromtimestamp(found_udp,timezone.utc)},{time_diff}", file=f)
            f.close()
            return None
    except Exception as e:
        print(f"Error when analyzing pcapng file: {e}")
    
    finally:
        cap.close()

def linux(output_path):
    # Step 1: Open Discord
    subprocess.Popen(['discord', '--no-sandbox', '&'])

    # Step 2: Wait for Discord to start (~20 seconds)
    time.sleep(10)

    first = True
    for i in range(400):
        # Step 3: Press CTRL + K
        pyautogui.hotkey('ctrl', 'k')
        channel = channel_2
        if first:
            channel = channel_1
        # Step 4: Type 'UMD-Relay'
        process = start_pcap(i, output_path)
        time.sleep(2)
        pyautogui.typewrite("{} {}".format(channel, server_name))
        time.sleep(2)

        # Step 5: Press Enter
        pyautogui.press('enter')
        time.sleep(2)

         # Step 6: Start packet collection
        # capture_pcap(i, output_path)
        stop_pcap(process)

        # Step 7: Analyze packet
        cap, destination = analyze_pcapng(i, output_path)
        process_pcap_analysis(cap, destination, i, output_path, blocking_status == "blocking", 0)

        first = not first

def mac_experiment():
    shutil.copy(path_to_pf, "/etc/backup_pf.conf")
    # capture_pcap()
        # Step 1: Open Discord
    subprocess.Popen(['open', '-a', 'Discord'])

    # Step 2: Wait for Discord to start (~20 seconds)
    time.sleep(3)

    first = True
    for i in range(4):
        # Step 3: Press CMD + K (equivalent to CTRL + K on Mac for Discord)
        with pyautogui.hold(['command']):
            time.sleep(1)
            pyautogui.press('k')
        process = start_pcap(i, output_path)

        # Step 4: Type 'UMD-Relay'
        channel = channel_2
        if first:
            channel = channel_1
        pyautogui.typewrite("{} {}".format(channel, server_name))

        # Step 5: Press Enter
        pyautogui.press('enter')

        # Step 6: Start packet collection
        # capture_pcap(i, './pcap_files')
        stop_pcap(process)

        # Step 7: Analyze packet
        cap, destination = analyze_pcapng(i, output_path)
        process_pcap_analysis(cap, destination, i, output_path, blocking_status == "blocking", 0)
        
        first = not first

if __name__ == "__main__":
    version = sys.argv[1]
    output_path = sys.argv[2]
    blocking_status = sys.argv[3]
    if version == "linux":
        linux(output_path)
    else:
        is_mac = True
        mac_experiment()