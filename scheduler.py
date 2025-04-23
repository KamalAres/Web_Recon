#!/usr/bin/env python3
"""
Scheduler Module

This module provides functionality for scheduling recurring reconnaissance tasks.
"""

import os
import json
import time
import datetime
import importlib.util
import subprocess
import sys

class ReconScheduler:
    """Class for scheduling reconnaissance tasks"""
    
    def __init__(self, schedule_file="scheduled_tasks.json"):
        """
        Initialize the scheduler
        
        Args:
            schedule_file (str): Path to the file storing scheduled tasks
        """
        self.schedule_file = schedule_file
        self.has_apscheduler = self._check_module("apscheduler")
    
    def _check_module(self, module_name):
        """Check if a Python module is available"""
        return importlib.util.find_spec(module_name) is not None
    
    def schedule(self, domain, interval, args):
        """
        Schedule a recurring reconnaissance task
        
        Args:
            domain (str): Domain to scan
            interval (str): Interval in format: 1h, 1d, 1w (hours, days, weeks)
            args (dict): Arguments for the scan
        
        Returns:
            bool: True if scheduling was successful, False otherwise
        """
        if not self.has_apscheduler:
            print("Error: apscheduler module not installed. Install with: pip install apscheduler")
            return False
        
        try:
            # Parse interval
            interval_seconds = self._parse_interval(interval)
            if interval_seconds is None:
                print(f"Error: Invalid interval format: {interval}")
                return False
            
            # Convert args to a serializable format
            args_dict = vars(args) if hasattr(args, '__dict__') else dict(args)
            
            # Create task entry
            task = {
                "domain": domain,
                "interval": interval,
                "interval_seconds": interval_seconds,
                "args": args_dict,
                "next_run": time.time() + interval_seconds,
                "created_at": time.time()
            }
            
            # Load existing tasks
            tasks = self._load_tasks()
            
            # Add or update task
            task_updated = False
            for i, existing_task in enumerate(tasks):
                if existing_task.get("domain") == domain:
                    tasks[i] = task
                    task_updated = True
                    break
            
            if not task_updated:
                tasks.append(task)
            
            # Save tasks
            self._save_tasks(tasks)
            
            # Set up scheduler
            self._setup_scheduler(tasks)
            
            print(f"Scheduled recurring scan for {domain} with interval {interval}")
            print(f"Next scan will run at {datetime.datetime.fromtimestamp(task['next_run'])}")
            
            return True
            
        except Exception as e:
            print(f"Error scheduling task: {str(e)}")
            return False
    
    def _parse_interval(self, interval):
        """Parse interval string to seconds"""
        try:
            if not interval:
                return None
            
            # Extract number and unit
            if interval.endswith('h'):
                return int(interval[:-1]) * 3600  # hours to seconds
            elif interval.endswith('d'):
                return int(interval[:-1]) * 86400  # days to seconds
            elif interval.endswith('w'):
                return int(interval[:-1]) * 604800  # weeks to seconds
            else:
                return None
        except ValueError:
            return None
    
    def _load_tasks(self):
        """Load scheduled tasks from file"""
        if not os.path.exists(self.schedule_file):
            return []
        
        try:
            with open(self.schedule_file, 'r') as f:
                return json.load(f)
        except Exception as e:
            print(f"Error loading scheduled tasks: {str(e)}")
            return []
    
    def _save_tasks(self, tasks):
        """Save scheduled tasks to file"""
        try:
            with open(self.schedule_file, 'w') as f:
                json.dump(tasks, f, indent=4)
        except Exception as e:
            print(f"Error saving scheduled tasks: {str(e)}")
    
    def _setup_scheduler(self, tasks):
        """Set up the scheduler with the tasks"""
        if not self.has_apscheduler:
            return
        
        try:
            from apscheduler.schedulers.background import BackgroundScheduler
            from apscheduler.triggers.interval import IntervalTrigger
            
            # Create scheduler
            scheduler = BackgroundScheduler()
            
            # Add jobs for each task
            for task in tasks:
                domain = task.get("domain")
                interval_seconds = task.get("interval_seconds")
                args_dict = task.get("args", {})
                
                # Create command arguments
                cmd_args = [sys.executable, "main.py", "-d", domain]
                
                # Add other arguments
                for key, value in args_dict.items():
                    if key == "domain":
                        continue  # Already added
                    
                    if isinstance(value, bool) and value:
                        cmd_args.append(f"--{key.replace('_', '-')}")
                    elif not isinstance(value, bool):
                        cmd_args.append(f"--{key.replace('_', '-')}")
                        cmd_args.append(str(value))
                
                # Add job to scheduler
                scheduler.add_job(
                    self._run_scan,
                    IntervalTrigger(seconds=interval_seconds),
                    args=[cmd_args, domain],
                    id=f"scan_{domain}",
                    replace_existing=True
                )
            
            # Start scheduler if not already running
            if not scheduler.running:
                scheduler.start()
                print("Scheduler started")
            
        except Exception as e:
            print(f"Error setting up scheduler: {str(e)}")
    
    def _run_scan(self, cmd_args, domain):
        """Run a scan as a subprocess"""
        try:
            print(f"Running scheduled scan for {domain} at {datetime.datetime.now()}")
            print(f"Command: {' '.join(cmd_args)}")
            
            # Run the scan
            result = subprocess.run(cmd_args, capture_output=True, text=True)
            
            # Log the result
            log_file = f"scheduled_scan_{domain}_{int(time.time())}.log"
            with open(log_file, 'w') as f:
                f.write(f"=== STDOUT ===\n{result.stdout}\n\n=== STDERR ===\n{result.stderr}")
            
            print(f"Scan completed. Log saved to {log_file}")
            
            # Update next run time
            tasks = self._load_tasks()
            for task in tasks:
                if task.get("domain") == domain:
                    task["last_run"] = time.time()
                    task["next_run"] = time.time() + task.get("interval_seconds", 86400)
                    break
            
            self._save_tasks(tasks)
            
        except Exception as e:
            print(f"Error running scheduled scan: {str(e)}")

if __name__ == "__main__":
    import argparse
    
    parser = argparse.ArgumentParser(description='Reconnaissance scheduler')
    parser.add_argument('-d', '--domain', required=True, help='Domain to scan')
    parser.add_argument('-i', '--interval', required=True, help='Interval (e.g., 1h, 1d, 1w)')
    parser.add_argument('-o', '--output-dir', default="./output", help='Output directory for results')
    parser.add_argument('--list', action='store_true', help='List scheduled tasks')
    parser.add_argument('--remove', action='store_true', help='Remove scheduled task for domain')
    
    args = parser.parse_args()
    
    scheduler = ReconScheduler()
    
    if args.list:
        tasks = scheduler._load_tasks()
        if not tasks:
            print("No scheduled tasks")
        else:
            print("Scheduled tasks:")
            for task in tasks:
                next_run = datetime.datetime.fromtimestamp(task.get("next_run", 0))
                print(f"  {task.get('domain')}: every {task.get('interval')} (next: {next_run})")
    elif args.remove:
        tasks = scheduler._load_tasks()
        tasks = [task for task in tasks if task.get("domain") != args.domain]
        scheduler._save_tasks(tasks)
        print(f"Removed scheduled task for {args.domain}")
    else:
        scheduler.schedule(args.domain, args.interval, {"output_dir": args.output_dir})