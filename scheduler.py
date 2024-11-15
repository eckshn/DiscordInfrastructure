import subprocess
import time
from datetime import datetime, timedelta

script_path = './main.py'

def run_experiment_script():
    try:
        subprocess.run(['python3', script_path], check=True)
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
        run_experiment_script()
        next_run = get_next_run_time()
        time_to_wait = (next_run - datetime.now()).total_seconds()
        print(f"Next run scheduled for: {next_run}")
        time.sleep(time_to_wait)  # Sleep until the next run time

if __name__ == "__main__":
    schedule_script()