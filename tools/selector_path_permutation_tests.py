# This simple test framework is for running selector path permutation tests
#  P4C's ptf framework might be more versatile, but is too havy for now as
#  it requires a lot of dependencies and we need some flexible sniffing to check 
#  outputs. Maybe use it later if this framework is not enough.

# Currently I simply use io to inject cmds to the runtime CLI, but using the
#  p4truntime that uses protobuf is better, as it is more robust. 

import argparse
import os
import shutil
import logging
import subprocess
import sys
import time
import signal
import json
from scapy.all import Ether, sendp, AsyncSniffer, Packet
from runtime_CLI import *

logging.basicConfig(level=logging.DEBUG, format='%(levelname)s - %(message)s')

# This is setup by veth_setup.sh
# should the shell script be part of this script??
SWITCH_VETH_INTF = "-i 0@veth0 -i 1@veth2 -i 2@veth4 -i 3@veth6 -i 4@veth8 -i 5@veth10"
TEST_LOG_DIR = "test_logs"
SW_LOG_FILE = "switch.log"
CLI_LOG_FILE = "runtime_cli.log"
THRIFT_IP = "127.0.0.1"
THRIFT_PORT = 9090

TMP_TEST = "../src/output_all_pkts/tests/pragma/rr.json" 


class TestCase:
    """
    A class to represent a test case for selector path permutation tests.
    """
    def __init__(self, name: str, p4_json: str, cli_cmds: list,
                 input_packets: list, expected_outputs: list):
        self.name = name
        self.p4_json = p4_json
        self.cli_cmds = cli_cmds
        self.input_packets = input_packets  # List of input packets to send
        self.expected_outputs = expected_outputs  # List of expected output packets
        self.sniffers: list[AsyncSniffer] = []  # List of sniffers for capturing packets
        self.exp_output_per_intf: dict[str, list] = {}  # Expected output packets per interface
        self.success_counter: dict[str, int] = {}  # Counter for successful outputs per interface
        self.passed = True 

    def __str__(self):
        return f"TestCase(name={self.name}, p4_json={self.p4_json}, cli_cmds={self.cli_cmds})"
    
    def to_string(self, description: str = None) -> str:
        if description:
            description = "\n".join([f"     {line.strip()}" for line in description.splitlines()])

        return f"TestCase: {self.name}\n" + \
               (f"  Description:\n{description}\n" if description else "")
    
    def get_expected_output_per_intf(self) -> dict[str, list]:
        """
        Returns a dictionary mapping egress interfaces to expected output packets.
        
        Returns:
            dict: A dictionary where keys are egress interfaces and values are lists of expected packets.
        """
        output_map = {}
        for output in self.expected_outputs:
            egress_intf = output.get("egress_intf")
            if egress_intf not in output_map:
                output_map[egress_intf] = []
            output_map[egress_intf].append(output.get("packet"))
        return output_map
    
    def process_sniffed_pkts(self, pkt: Packet):
        """
        Processes sniffed packets and updates the success counter.
        
        Args:
            pkt (Packet): The sniffed packet to process.
        """
        intf = pkt.sniffed_on
        p = bytes(pkt).hex()
        logging.debug(f"Processing packet on interface {intf}: {p}")
        if intf not in self.success_counter:
            logging.error(f"Interface {intf} not found in expected outputs.")
            self.passed = False
            return
        
        expected_pkts = self.exp_output_per_intf.get(intf, [])
        if not expected_pkts:
            logging.error(f"No expected outputs for interface {intf}.")
            self.passed = False
            return
        
        # Check if the packet matches any expected output
        for exp_pkt in expected_pkts:
            if p == exp_pkt:
                # One sniffer per intf, so no need to lock it. 
                self.success_counter[intf] += 1
                logging.debug(f"Packet matched expected output on interface {intf}: {pkt.summary()}")
                self.exp_output_per_intf[intf].remove(exp_pkt)
                return
            
        logging.error(f"Packet on interface {intf} did not match any expected output: {p}")
        self.passed = False 


    def check_success(self):
        """
        Checks if all expected outputs have been captured successfully.
        
        """
        for intf, expected_pkts in self.exp_output_per_intf.items():
            if len(expected_pkts) > 0:
                logging.error(f"Not all expected packets were captured on interface {intf}. "
                              f"Remaining: {len(expected_pkts)}, Captured: {self.success_counter[intf]}")
                self.passed = False
            else:
                logging.debug(f"All expected packets captured on interface {intf}.")


    def get_sniffers(self) -> list[tuple[AsyncSniffer, str]]:
        """
        Returns a list of AsyncSniffer objects for each expected output.
        Each sniffer is configured to capture packets on the specified interface.
        
        Returns:
            list[AsyncSniffer]: A list of AsyncSniffer objects.
        """
        sniffers = []

        for intf, packets in self.exp_output_per_intf.items():
            self.success_counter[intf] = 0  # Initialize success counter for each interface
            sniffer = AsyncSniffer(iface=intf, prn=lambda pkt: self.process_sniffed_pkts(pkt),
                                   store=False, count=len(packets)) 
            sniffer.start()
            sniffers.append([sniffer, intf])  # Store the sniffer and its interface

        return sniffers
    
    def send_input_packets(self):
        """
        Sends input packets defined in the test case.
        """
        for pkt in self.input_packets:
            intf = pkt.get("ingress_intf")
            packet = Ether(bytes.fromhex(pkt.get("packet")))
            logging.debug(f"Sending packet on interface {intf}: {pkt.get("packet")}")
            sendp(packet, iface=intf, verbose=False)

    
    def run(self) -> bool:
        """
        Runs the test case by sending input packets and checking expected outputs.

        Returns:
            bool: True if the test case passed, False otherwise.
        """
        logging.info(f"Running test case: {self.name}")
        self.exp_output_per_intf = self.get_expected_output_per_intf()
        sniffers = self.get_sniffers()
        self.send_input_packets()
        time.sleep(3)  # Wait for packets to be sent and captured
        # wait for sniffers upto 2 seconds to capture packets
        for sniffer, intf in sniffers:
            sniffer.join(timeout=2)
            if sniffer.thread.is_alive():
                logging.warning(f"Sniffer on interface {intf} did not capture all expected packets.")
            else:
                logging.debug(f"Sniffer on interface {intf} finished capturing packets.")

        self.check_success()
        logging.info(f"Test case '{self.name}' completed. Status: {"Passed" if self.passed else "Failed"}")
        return self.passed
        




class PathPermutationTestRunner:
    """
    A class to run selector path permutation tests.
    """
    
    def __init__(self, switch_path: str, runtime_cli_path: str, test_registry:str):
        self.switch_path = switch_path
        self.runtime_cli_path = runtime_cli_path
        self.test_registry = test_registry
        # switch and runtime CLI processes
        self.sw: subprocess.Popen = None
        self.cli: subprocess.Popen = None
        self.test_cases: list[TestCase] = []
        self.log_dir = os.path.join(os.path.dirname(test_registry), TEST_LOG_DIR)

    def load_test_cases(self) -> list[TestCase]:
        """
        Loads test cases from the test registry JSON file.
        
        Returns:
            list[TestCase]: A list of TestCase objects.
        """
        if not os.path.exists(self.test_registry):
            logging.error(f"Test registry file '{self.test_registry}' does not exist.")
            return []

        with open(self.test_registry, 'r') as f:
            data = json.load(f)
        test_dir = os.path.dirname(self.test_registry)
        test_cases = []
        for test in data.get("tests", []):
            name = test.get("name")
            if test.get("enabled", False) is False:
                logging.info(f"Test '{name}' is disabled. Skipping.")
                continue
            p4_json = test.get("program")
            if not p4_json:
                logging.warning(f"Test '{name}' does not have a P4 JSON file specified. Skipping.")
                continue
            p4_json_path = os.path.join(test_dir, p4_json)
            if not os.path.exists(p4_json_path):
                logging.error(f"P4 JSON file '{p4_json_path}' for test '{name}' does not exist. Skipping.")
                continue
            cli_cmds = test.get("runtime_cli_commands", [])
            if not isinstance(cli_cmds, list):
                logging.error(f"CLI commands for test '{name}' are not in list format. Skipping.")
                continue
            if len(cli_cmds) == 0:
                logging.warning(f"No CLI commands specified for test '{name}'.")
            input_packets = test.get("input_packets", [])
            if not isinstance(input_packets, list):
                logging.error(f"Input packets for test '{name}' are not in list format. Skipping.")
                continue
            expected_outputs = test.get("expected_outputs", [])
            if not isinstance(expected_outputs, list):
                logging.error(f"Expected outputs for test '{name}' are not in list format. Skipping.")
                continue

            test_case = TestCase(name=name, p4_json=p4_json_path, cli_cmds=cli_cmds,
                                 input_packets=input_packets, expected_outputs=expected_outputs)
            logging.info(f"{test_case.to_string(test.get('description'))}")
            test_cases.append(test_case)
        if not test_cases:
            logging.error("No valid test cases found in the test registry.")
        else:
            logging.info(f"Loaded {len(test_cases)} test cases from the registry.")
        return test_cases


    def start_switch(self, p4_json: str, log_file=SW_LOG_FILE):
        """
        Starts the switch executable using subprocess.Popen.
        
        Args:
            p4_json (str): The path to the P4 JSON file.
        """
        switch_exe = self.switch_path

        try:
            logging.info("Starting the switch...")
            with open(log_file, "w") as f:
                # Ensure the log file is created and truncated
                pass
            logging.info(f"Logging output to {log_file}")

            cmd = [switch_exe, p4_json, SWITCH_VETH_INTF, 
                   f"--pcap={os.path.dirname(log_file)}", "--log-console",
                    "-Ltrace", "--thrift-port", str(THRIFT_PORT), ">", log_file]
            
            switch_exe = " ".join(cmd)
            logging.debug(f"Switch command: {switch_exe}")
            
            # Start the switch process
            self.sw = subprocess.Popen(switch_exe, shell=True, stdout=subprocess.PIPE,
                                        stderr=sys.stdout, 
                                        text=True, preexec_fn=os.setsid)
            if not self.sw:
                logging.error("Failed to start the switch. Exiting.")
                raise
            logging.info("Switch started successfully.")
        except Exception as e:
            logging.error(f"Failed to start the switch executable: {e}")
            raise 

    def setup_runtime_cli(self, log_file = CLI_LOG_FILE) -> subprocess.Popen:
        """
        Sets up the runtime CLI for the switch.
        """
        runtime_cli_path = self.runtime_cli_path
        try:
            logging.info("Setting up the runtime CLI...")
            cmd = ["python3", runtime_cli_path, "--thrift-ip", THRIFT_IP,
                    "--thrift-port", str(THRIFT_PORT), "--pre","SimplePreLAG",
                    ">",log_file]
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

    def setup_testbed(self, test_case: TestCase):
        """
        Sets up the testbed for a given test case by starting the switch and runtime CLI,
        and executing the CLI commands specified in the test case.
        Args:
            test_case (TestCase): The test case to set up.
        """
        try:
            logging.debug(f"Setup test case: {test_case.name}")
            log_dir = os.path.join(self.log_dir, test_case.name)
            if not os.path.exists(log_dir):
                os.makedirs(log_dir)
            sw_log_file = os.path.join(log_dir, 
                                       f"{test_case.name}_{SW_LOG_FILE}")
            cli_log_file = os.path.join(log_dir, 
                                        f"{test_case.name}_{CLI_LOG_FILE}")
            self.start_switch(test_case.p4_json, sw_log_file)
            time.sleep(0.5)  # Wait for the switch to initialize
            self.setup_runtime_cli(cli_log_file)
            time.sleep(0.5)  # Wait for the CLI to initialize
            
            for cmd in test_case.cli_cmds:
                self.execute_cli_command(cmd)
                time.sleep(0.1)  # Allow some time for command input, not stable..
            
            logging.debug(f"Test case '{test_case.name}' setup successfully.")
        except Exception as e:
            logging.error(f"Error running test case '{test_case.name}': {e}")
            
    def packet_sending_and_sniffing(self, test_case: TestCase):
        """
        Placeholder for packet sending and sniffing logic.
        This function should implement the logic to send packets and sniff responses
        based on the test case configuration.

        Maybe a class for this is better as it does a lot

        1. Reading the input pkt from test case (add corresponding field in TestCase)
        2. Setup proper AsyncSniffer to capture packets, corresponding the expected output,
            like the number of output pkts, the expected output interface, etc.
        3. Send the packet using Scapy's sendp function
        4. Wait for the sniffer to capture packets, should have timeout
        5. Process the captured packets, e.g., check if they match expected output
        6. Log the results, e.g., number of packets captured, any discrepancies
        7. Cleanup the sniffer and any resources used


        
        Args:
            test_case (TestCase): The test case to run.
        """
        pass

    def run_tests(self):
        """
        Runs all test cases loaded from the test registry.
        """
        test_cases = self.load_test_cases()
        log_dir = self.log_dir
        if not os.path.exists(log_dir):
            os.makedirs(log_dir)
        else:
            logging.warning(f"Test log directory '{log_dir}' already exists. Testing aborting to avoid overwriting logs.")
            return
                
        logging.info(f"Test log directory: {log_dir}")
        if not os.path.isdir(log_dir):
            logging.error(f"Test log directory '{log_dir}' is not a directory.")
            return
        
        if not test_cases:
            logging.error("No test cases found to run.")
            return
        
        # The actual testing logic
        for test_case in test_cases:
            logging.info(f"Running test case: {test_case.name}")
            self.setup_testbed(test_case)
            test_case.run()

            self.cleanup()

def main():
    parser = argparse.ArgumentParser(description="Run selector path permutation tests.")
    parser.add_argument("--switch-executable","-s", type=str, default="simple_switch",
                        help="Target switch to run the tests on (default: simple_switch)")
    parser.add_argument("--runtime-cli", "-r", type=str, required=True,
                        help="Path to the runtime CLI script (runtime_CLI.py).")
    parser.add_argument("--test-registry", "-t", type=str, required=True,
                        help="Path to the test registry JSON file containing test cases.")
    
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

    try:
        runner = PathPermutationTestRunner(switch_exe, runtime_cli_path, args.test_registry)
        runner.run_tests()
    except Exception as e:
        logging.error(f"An error occurred while running the tests: {e}")
    finally:
        runner.cleanup()


if __name__ == "__main__":
    main()