import subprocess
import time
from datetime import datetime, timedelta
import sys

script_path = './main.py'
version = ""
blocking_status = ""


def run_experiment_script(output_dir):
    try:
        subprocess.run(['sudo', 'python3', script_path, version, output_dir, blocking_status], check=True)
        print(f"Successfully ran {script_path}")
    except subprocess.CalledProcessError as e:
        print(f"Script {script_path} failed with error: {e}")
    except Exception as e:
        print(f"An unexpected error occurred: {e}")

def get_next_run_time():
    now = datetime.now()
    # Round to the nearest future 2-hour mark
    next_hour = now.hour + 2
    if next_hour % 2 == 1:
        next_hour -= 1
    next_run = now.replace(hour=next_hour % 24, minute=0, second=0, microsecond=0)
    
    if next_run <= now:  # Ensure we don't pick a time in the past
        next_run += timedelta(hours=2)
    
    return next_run

def schedule_script():
    for i in range(12):
        try:
            subprocess.run(['sudo', 'ufw', '--force', 'reset'], check=True)
            print(f"Successfully reset ufw")
        except subprocess.CalledProcessError as e:
            print(f"Script {script_path} failed with error: {e}")
        except Exception as e:
            print(f"An unexpected error occurred: {e}")
        
        run_experiment_script(f"./pcap_files/{i}_test")
        # next_run = get_next_run_time()
        # time_to_wait = (next_run - datetime.now()).total_seconds()
        # print(f"Next run scheduled for: {next_run}")
        # print(time_to_wait)
        
        # Run every 45 minutes
        print('running')
        # time.sleep(45 * 60)  # Sleep until the next run time

if __name__ == "__main__":
    version = sys.argv[1]
    blocking_status = sys.argv[2]
    schedule_script()