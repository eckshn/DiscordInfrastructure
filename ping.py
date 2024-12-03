import csv
import subprocess
import time

def ping_ip(ip):
    """
    Pings an IP address and returns the round-trip time (RTT) in milliseconds.
    If the ping fails, returns None.
    """
    try:
        # Run the ping command (5 packets)
        result = subprocess.run(
            ['ping', '-c', '1', ip],
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True
        )
        # Check if the ping was successful
        if result.returncode == 0:
            # Parse the output to extract RTT
            for line in result.stdout.split('\n'):
                if "time=" in line:
                    # Extract the time value after "time="
                    return float(line.split("time=")[-1].split(" ")[0])
        else:
            print(f"Ping to {ip} failed. Output: {result.stdout}")
            return None
    except Exception as e:
        print(f"Error pinging {ip}: {e}")
        return None


def process_csv(file_path, output_path):
    """
    Reads a CSV file, pings the IPs in the last column, and writes the results to a new CSV file.

    Arguments:
    file_path -- Input CSV file path
    output_path -- Output CSV file path with results
    """
    try:
        with open(file_path, 'r') as infile, open(output_path, 'w', newline='') as outfile:
            reader = csv.reader(infile)
            writer = csv.writer(outfile)

            # Read header and append new column for ping results
            # header = next(reader)
            # writer.writerow(header + ['Ping Time (ms)'])

            for row in reader:
                if len(row) < 9:
                    # Did not find an IP
                    print("skipping...")
                    writer.writerow(row + ['NO IP TO PING'])
                    continue
                ip = row[-1]  # Last column contains the IP address
                print(f"Pinging {ip}...")
                start_time = time.time()
                ping_time = ping_ip(ip)  # Ping the IP
                elapsed_time = time.time() - start_time

                if ping_time is not None:
                    print(f"Ping to {ip} successful: {ping_time} ms")
                else:
                    print(f"Ping to {ip} failed after {elapsed_time:.2f} seconds.")

                # Append ping time (or 'Failed' if None) to the row and write to output
                writer.writerow(row + [ping_time if ping_time is not None else 'Failed'])

        print(f"Results written to {output_path}")

    except Exception as e:
        print(f"Error processing file: {e}")

# Example usage
input_csv = './pcap_files/9_test/results.csv'  # Replace with your input CSV file path
output_csv = 'output10.csv'  # Replace with your desired output CSV file path
process_csv(input_csv, output_csv)