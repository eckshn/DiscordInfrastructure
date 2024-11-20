import pyautogui
import time
import subprocess
import os
import pyshark
import shutil
from datetime import timezone
from collections import Counter
import datetime
import signal

channel_1 = "connection_1"
channel_2 = "connection_2"
server_name = "Livestream"
path_to_pf = "/etc/pf.conf"
global_timings = {}
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
    return

def capture_pcap(n, output='./pcap_files'):
    os.makedirs(output, exist_ok=True)

    # Define the command to run tcpdump
    command = ['timeout', '--signal=SIGKILL', '10', 'sudo', 'tcpdump', 'net', '66.22.0.0/16', '-w', os.path.join(output, f'{n}.pcapng')]
    print('writing to: ', os.path.join(output, f'{n}.pcapng'))

    try:
        # Start the tcpdump process
        process = subprocess.Popen(command)
        # # Wait for 5 seconds
        # time.sleep(5)
        
        # # Stop the tcpdump process
        # if is_mac:
        #     process.terminate()
        #     process.wait()
        
        # # os.killpg(os.getpgid(process.pid), signal.SIGINT)
        # process.terminate()
        # process.wait()

       # process.send_signal(signal.SIGINT)
        #process.terminate()
        process.wait()
        print('ended')
        #process.wait()  # Ensure the process has terminated
        print("Capture completed and saved to capture.pcap.")
        
    except subprocess.CalledProcessError as e:
        print(f"Error while running tcpdump: {e}")
    except KeyboardInterrupt:
        print("Capture stopped by user.")
    finally:
        if process.poll() is None:
            # Ensure the process is terminated if it didn't stop
            os.killpg(os.getpgid(process.pid), signal.SIGKILL)
            print("Forcefully killed tcpdump.")

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
    try:
        
        for packet in cap:
            if found_first == 0:
                found_first = float(packet.sniff_timestamp) # THE VERY FIRST PACKET
            if 0 == found_tcp and 'TCP' in packet and ".".join(packet.ip.dst.split(".")[:2]) in ["66.22"]: # ["206.247","144.195","134.224"]:
                found_tcp = float(packet.sniff_timestamp)
            if 'IP' in packet and "UDP" in packet:
                # Media exchange packets have length 1044 so they're easy to fingerprint
                if packet.udp.length >= "50":
                    if 0 == found_udp:
                        found_udp = float(packet.sniff_timestamp)
                    dst = packet.ip.dst
                    dst = ".".join(packet.ip.dst.split(".")[:2])
                    
                    # Look at the known Zoom IP prefixes
                    if dst == "66.22": # dst == "206.247" or dst == "144.195" or dst == "134.224":
                        destinations[packet.ip.dst] += 1
    
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
            print(f"{i+1},{datetime.datetime.now()},{i}.pcapng,{len(all_media_ips)},{datetime.datetime.fromtimestamp(found_first,timezone.utc)},{datetime.datetime.fromtimestamp(found_tcp,timezone.utc)},{datetime.datetime.fromtimestamp(found_udp,timezone.utc)},{','.join(all_media_ips)}", file=f)
            f.close()

            print(f"Finish the {i+1}th iteration\n")
        else:
            f = open(os.path.join(output,"results.csv"), "a")
            print("\n No destination IP found, please check the pcapng file")
            print(f"{i+1},{datetime.datetime.now()},{i+1}.pcapng,0,{global_timings[i]},{datetime.datetime.fromtimestamp(found_first,timezone.utc)},{datetime.datetime.fromtimestamp(found_tcp,timezone.utc)},{datetime.datetime.fromtimestamp(found_udp,timezone.utc)}", file=f)
            f.close()
            return None
    except Exception as e:
        print(f"Error when analyzing pcapng file: {e}")
    
    finally:
        cap.close()

def linux():
    # Step 1: Open Discord
    subprocess.Popen(['discord', '--no-sandbox', '&'])

    # Step 2: Wait for Discord to start (~20 seconds)
    time.sleep(20)

    first = True
    for i in range(2):
        # Step 3: Press CTRL + K
        pyautogui.hotkey('ctrl', 'k')
        channel = channel_2
        if first:
            channel = channel_1
        # Step 4: Type 'UMD-Relay'
        time.sleep(2)
        pyautogui.typewrite("{} {}".format(channel, server_name))
        time.sleep(2)

        # Step 5: Press Enter
        pyautogui.press('enter')
        time.sleep(2)

         # Step 6: Start packet collection
        capture_pcap(i, './pcap_files')

        # Step 7: Analyze packet
        cap, destination = analyze_pcapng(i, './pcap_files')
        process_pcap_analysis(cap, destination, i, './pcap_files', False, 0)

        first = not first

def mac_experiment():
    shutil.copy(path_to_pf, "/etc/backup_pf.conf")
    # capture_pcap()
        # Step 1: Open Discord
    subprocess.Popen(['open', '-a', 'Discord'])

    # Step 2: Wait for Discord to start (~20 seconds)
    time.sleep(3)

    first = True
    for i in range(100):
        # Step 3: Press CMD + K (equivalent to CTRL + K on Mac for Discord)
        with pyautogui.hold(['command']):
            time.sleep(1)
            pyautogui.press('k')
        # pyautogui.hotkey('command', 'k')

        # Step 4: Type 'UMD-Relay'
        channel = channel_2
        if first:
            channel = channel_1
        pyautogui.typewrite("{} {}".format(channel, server_name))

        # Step 5: Press Enter
        pyautogui.press('enter')

        # Step 6: Start packet collection
        capture_pcap(i, './pcap_files')

        # Step 7: Analyze packet
        cap, destination = analyze_pcapng(i, './pcap_files')
        process_pcap_analysis(cap, destination, i, './pcap_files', True, 0)
        
        first = not first

linux()