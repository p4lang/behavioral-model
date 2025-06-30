import argparse
import os
import shutil
import logging
import subprocess
import sys
import time
import signal
from runtime_CLI import *

logging.basicConfig(level=logging.DEBUG, format='%(levelname)s - %(message)s')

# This is setup by veth_setup.sh
# should the shell script be part of this script??
SWITCH_VETH_INTF = "-i 0@veth0 -i 1@veth2 -i 2@veth4 -i 3@veth6 -i 4@veth8 -i 5@veth10"
SW_LOG_FILE = "switch.log"
CLI_LOG_FILE = "runtime_cli.log"
THRIFT_IP = "127.0.0.1"
THRIFT_PORT = 9090

temp_test_cfg = "../src/output_all_pkts/tests/pragma/rr.json" 

class PathPermutationTestRunner:
    """
    A class to run selector path permutation tests.
    
    Attributes:
        switch_exe (str): The path to the switch executable.
        runtime_cli_path (str): The path to the runtime CLI script.
        test_dir (str): The directory where the tests (p4 json) are located.
    """
    
    def __init__(self, switch_path, runtime_cli_path, test_dir):
        self.switch_path = switch_path
        self.runtime_cli_path = runtime_cli_path
        self.test_dir = test_dir
        # switch and runtime CLI processes
        self.sw: subprocess.Popen = None
        self.cli: subprocess.Popen = None

    def start_switch(self, p4_json, log_file=SW_LOG_FILE):
        """
        Starts the switch executable using subprocess.Popen.
        
        Args:
            p4_json (str): The path to the P4 JSON file.
        """
        switch_exe = self.switch_path

        try:
            logging.info("Starting the switch...")
            with open(log_file, "w") as f:
                # TODO: log per testcase
                # Ensure the log file is created and truncated
                pass
            logging.info(f"Logging output to {log_file}")

            cmd = [switch_exe, p4_json, SWITCH_VETH_INTF, "--pcap",
                    "-Ldebug", "--thrift-port", str(THRIFT_PORT), ">", log_file]
            
            switch_exe = " ".join(cmd)
            logging.debug(f"Switch command: {switch_exe}")
            
            # Start the switch process
            self.sw = subprocess.Popen(switch_exe, shell=True, stdout=subprocess.PIPE,
                                        stderr=sys.stdout, stdin=subprocess.PIPE, 
                                        text=True, preexec_fn=os.setsid)
            if not self.sw:
                logging.error("Failed to start the switch. Exiting.")
                raise
            logging.info("Switch started successfully.")
        except Exception as e:
            logging.error(f"Failed to start the switch executable: {e}")
            raise 

    def setup_runtime_cli(self) -> subprocess.Popen:
        """
        Sets up the runtime CLI for the switch.
        """
        runtime_cli_path = self.runtime_cli_path
        try:
            logging.info("Setting up the runtime CLI...")
            cmd = ["python3", runtime_cli_path, "--thrift-ip", THRIFT_IP,
                    "--thrift-port", str(THRIFT_PORT), "--pre","SimplePreLAG",
                    ">", CLI_LOG_FILE]
            cli_exe = " ".join(cmd)
            logging.debug(f"Runtime CLI command: {cli_exe}")
            self.cli = subprocess.Popen(cli_exe, shell=True, 
                                        stdout=subprocess.PIPE,
                                        stdin=subprocess.PIPE,
                                        stderr=sys.stderr, text=True)
            if not self.cli:
                logging.error("Failed to start the runtime CLI. Exiting.")
                raise
            logging.info("Runtime CLI started successfully.")
        except Exception as e:
            logging.error(f"Failed to start the runtime CLI: {e}")
            raise

    def execute_cli_command(self, command: str):
        """
        Executes a command in the runtime CLI.
        
        Args:
            command (str): The command to execute.
        """
        if not self.cli:
            logging.error("Runtime CLI is not running. Cannot execute command.")
            return
        
        try:
            logging.debug(f"Executing CLI command: {command}")
            self.cli.stdin.write(command + "\n")
            self.cli.stdin.flush()
        except Exception as e:
            logging.error(f"Failed to execute CLI command '{command}': {e}")


    def temp_test(self, p4_json=temp_test_cfg):
        try:
            self.start_switch(p4_json)
            time.sleep(0.5)  # Wait for the switch to initialize
            self.setup_runtime_cli()
            time.sleep(0.5)  # Wait for the switch and CLI to initialize
            
            # Example command to execute in the CLI
            self.execute_cli_command("show_ports")
            time.sleep(2)  # Wait for the command to execute
            logging.info("Temporary test executed successfully.")
        except Exception as e:
            logging.error(f"Error during temporary test execution: {e}")
        finally:
            self.cleanup()
    def cleanup(self):
        """
        Cleans up the switch and runtime CLI processes.
        """
        if self.sw:
            logging.debug("Terminating the switch process...")
            os.killpg(os.getpgid(self.sw.pid), signal.SIGTERM)
            self.sw = None
            logging.debug("Switch process terminated.")

        if self.cli:
            logging.debug("Terminating the runtime CLI process...")
            self.cli.kill()
            self.cli = None
            logging.debug("Runtime CLI process terminated.")




def main():
    parser = argparse.ArgumentParser(description="Run selector path permutation tests.")
    parser.add_argument("--switch-executable","-s", type=str, default="simple_switch",
                        help="Target switch to run the tests on (default: simple_switch)")
    parser.add_argument("--runtime-cli", "-r", type=str, required=True,
                        help="Path to the runtime CLI script (runtime_CLI.py).")
    
    args = parser.parse_args()

    switch_exe = args.switch_executable
    if not os.path.exists(switch_exe) and not shutil.which(switch_exe):
        logging.error(f"The switch executable '{switch_exe}' does not exist.")
        return
    logging.debug(f"Switch executable found: {switch_exe}")

    runtime_cli_path = args.runtime_cli
    if not os.path.exists(runtime_cli_path):
        logging.error(f"The runtime CLI script '{runtime_cli_path}' does not exist.")
        return
    logging.debug(f"Runtime CLI script found: {runtime_cli_path}")

    runner = PathPermutationTestRunner(switch_exe, runtime_cli_path, "")
    runner.temp_test()

    





if __name__ == "__main__":
    main()