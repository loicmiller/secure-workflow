###############################################################################
# Imports

import sys # Exit function
import os # OS functions
import argparse # Argument parser
import pprint # Pretty printing dicts

# Shell commands
import subprocess
from subprocess import Popen,PIPE
import shlex # Shell command parsing

from multiprocessing import Process, Lock # Parallel execution

from ast import literal_eval # String to dictionary
import re # Regular expressions

from scapy.all import * # Packet capture parsing


###############################################################################
# General utility

# Exit the program
def terminate_app(code):
    if not args.quiet:
        print("Exiting program...")
    sys.exit(code)


###############################################################################
# Argument parser

def get_parser():
    # Get parser for command line arguments
    parser = argparse.ArgumentParser(description="Tests for secure architecture")
    parser.add_argument("--version", action="version", version='%(prog)s 1.0')
    parser.add_argument("-v", "--verbose", action="count", default=0, help="increase output verbosity")
    parser.add_argument("-q", "--quiet", action="store_true", help="hide command outputs")
    parser.add_argument("-s", "--start", action="store_true", help="initialize Kubernetes for tests")
    parser.add_argument("-n", "--no-capture", action="store_true", help="do not capture")
    parser.add_argument("-p", "--policy-file", type=str, metavar="FILE", default="../service-mesh/custom_quick_start.yaml", help="policy file for capture checking")
    parser.add_argument("-d", "--capture-dir", type=str, metavar="DIR", default="packet_captures/", help="packet capture folder")
    parser.add_argument("-o", "--override-pods", type=str, metavar="NAME:IP...", default="", help="override pod IP addresses")
    parser.add_argument("-k", "--kill", action="store_true", help="stop Kubernetes before terminating program")

    return parser


###############################################################################
# Pod object

class Pod:
    def __init__(self, name=None):
        # Dummy pod for error handling
        if name is None:
            self.name = ""
            self.pod_id = ""
            self.pod_ip = ""
            self.service_ip = ""
            self.service_port = ""
        else:
            self.name = name
            self.pod_id = self.get_pod_id(name)
            assert(self.pod_id != ""), "Pod " + name + " does not exist."
            self.pod_ip = self.get_pod_ip(name)
            assert(self.pod_ip != ""), "Pod " + name + " has no IP."
            self.service_ip = self.get_service_ip(name)
            assert(self.service_ip != ""), "Pod " + name + " has no service IP."
            self.service_port = self.get_service_port(name)
            assert(self.service_port != ""), "Pod " + name + " has no service port."

    def __repr__(self):
        return "Pod({}, {}, {}, {}, {})".format(self.name, self.pod_id, self.pod_ip, self.service_ip, self.service_port)

    # Returns the pod ID
    def get_pod_id(self, name):
        get_pods = shlex.split("kubectl get pods")
        if args.verbose >= 2:
            print("Command: [{}]".format(", ".join(map(str, get_pods))))
        get_pods_p = Popen(get_pods,
                             stdout=subprocess.PIPE,
                             universal_newlines=True)

        grep = shlex.split("grep " + name)
        if args.verbose >= 2:
            print("Command: [{}]".format(", ".join(map(str, grep))))
        grep_p = Popen(grep,
                             stdin=get_pods_p.stdout,
                             stdout=subprocess.PIPE,
                             universal_newlines=True)
        get_pods_p.stdout.close()

        tr = shlex.split("tr -s ' '")
        if args.verbose >= 2:
            print("Command: [{}]".format(", ".join(map(str, tr))))
        tr_p = Popen(tr,
                             stdin=grep_p.stdout,
                             stdout=subprocess.PIPE,
                             universal_newlines=True)
        grep_p.stdout.close()

        cut = shlex.split("cut -d ' ' -f 1")
        if args.verbose >= 2:
            print("Command: [{}]".format(", ".join(map(str, cut))))
        cut_p = Popen(cut,
                             stdin=tr_p.stdout,
                             stdout=subprocess.PIPE,
                             universal_newlines=True)
        tr_p.stdout.close()

        awk = shlex.split("awk 'NR>1{print PREV} {PREV=$0} END{printf(\"%s\",$0)}'")
        if args.verbose >= 2:
            print("Command: [{}]".format(", ".join(map(str, awk))))
        awk_p = Popen(awk,
                             stdin=cut_p.stdout,
                             stdout=subprocess.PIPE,
                             universal_newlines=True)
        cut_p.stdout.close()

        output = awk_p.communicate()[0]
        if args.verbose >= 1:
            print("Pod '" + name + "' ID: " + output)
        return output


    # Returns the pod IP
    def get_pod_ip(self, name):
        get_pods = shlex.split("kubectl get pods -o wide")
        if args.verbose >= 2:
            print("Command: [{}]".format(", ".join(map(str, get_pods))))
        get_pods_p = Popen(get_pods,
                             stdout=subprocess.PIPE,
                             universal_newlines=True)

        grep = shlex.split("grep " + name)
        if args.verbose >= 2:
            print("Command: [{}]".format(", ".join(map(str, grep))))
        grep_p = Popen(grep,
                             stdin=get_pods_p.stdout,
                             stdout=subprocess.PIPE,
                             universal_newlines=True)
        get_pods_p.stdout.close()

        tr = shlex.split("tr -s ' '")
        if args.verbose >= 2:
            print("Command: [{}]".format(", ".join(map(str, tr))))
        tr_p = Popen(tr,
                             stdin=grep_p.stdout,
                             stdout=subprocess.PIPE,
                             universal_newlines=True)
        grep_p.stdout.close()

        cut = shlex.split("cut -d ' ' -f 6")
        if args.verbose >= 2:
            print("Command: [{}]".format(", ".join(map(str, cut))))
        cut_p = Popen(cut,
                             stdin=tr_p.stdout,
                             stdout=subprocess.PIPE,
                             universal_newlines=True)
        tr_p.stdout.close()

        awk = shlex.split("awk 'NR>1{print PREV} {PREV=$0} END{printf(\"%s\",$0)}'")
        if args.verbose >= 2:
            print("Command: [{}]".format(", ".join(map(str, awk))))
        awk_p = Popen(awk,
                             stdin=cut_p.stdout,
                             stdout=subprocess.PIPE,
                             universal_newlines=True)
        cut_p.stdout.close()

        output = awk_p.communicate()[0]
        if args.verbose >= 1:
            print("Pod '" + name + "' IP: " + output)
        return output


    # Get the IP of the service
    def get_service_ip(self, name):
        # kubectl get services | grep "adder" | tr -s ' ' | cut -d ' ' -f 5 | cut -d '/' -f 1
        get_services = shlex.split("kubectl get services")
        if args.verbose >= 2:
            print("Command: [{}]".format(", ".join(map(str, get_services))))
        get_services_p = Popen(get_services,
                             stdout=subprocess.PIPE,
                             universal_newlines=True)

        grep = shlex.split("grep " + name)
        if args.verbose >= 2:
            print("Command: [{}]".format(", ".join(map(str, grep))))
        grep_p = Popen(grep,
                             stdin=get_services_p.stdout,
                             stdout=subprocess.PIPE,
                             universal_newlines=True)
        get_services_p.stdout.close()

        tr = shlex.split("tr -s ' '")
        if args.verbose >= 2:
            print("Command: [{}]".format(", ".join(map(str, tr))))
        tr_p = Popen(tr,
                             stdin=grep_p.stdout,
                             stdout=subprocess.PIPE,
                             universal_newlines=True)
        grep_p.stdout.close()

        cut = shlex.split("cut -d ' ' -f 3")
        if args.verbose >= 2:
            print("Command: [{}]".format(", ".join(map(str, cut))))
        cut_p = Popen(cut,
                             stdin=tr_p.stdout,
                             stdout=subprocess.PIPE,
                             universal_newlines=True)
        tr_p.stdout.close()

        awk = shlex.split("awk 'NR>1{print PREV} {PREV=$0} END{printf(\"%s\",$0)}'")
        if args.verbose >= 2:
            print("Command: [{}]".format(", ".join(map(str, awk))))
        awk_p = Popen(awk,
                             stdin=cut_p.stdout,
                             stdout=subprocess.PIPE,
                             universal_newlines=True)
        cut_p.stdout.close()

        output = awk_p.communicate()[0]
        if args.verbose >= 1:
            print("Pod '" + name + "' service IP: " + output)
        return output


    # Get the port number of the service
    def get_service_port(self, name):
        # kubectl get services | grep "adder" | tr -s ' ' | cut -d ' ' -f 5 | cut -d '/' -f 1
        get_services = shlex.split("kubectl get services")
        if args.verbose >= 2:
            print("Command: [{}]".format(", ".join(map(str, get_services))))
        get_services_p = Popen(get_services,
                             stdout=subprocess.PIPE,
                             universal_newlines=True)

        grep = shlex.split("grep " + name)
        if args.verbose >= 2:
            print("Command: [{}]".format(", ".join(map(str, grep))))
        grep_p = Popen(grep,
                             stdin=get_services_p.stdout,
                             stdout=subprocess.PIPE,
                             universal_newlines=True)
        get_services_p.stdout.close()

        tr = shlex.split("tr -s ' '")
        if args.verbose >= 2:
            print("Command: [{}]".format(", ".join(map(str, tr))))
        tr_p = Popen(tr,
                             stdin=grep_p.stdout,
                             stdout=subprocess.PIPE,
                             universal_newlines=True)
        grep_p.stdout.close()

        cut = shlex.split("cut -d ' ' -f 5")
        if args.verbose >= 2:
            print("Command: [{}]".format(", ".join(map(str, cut))))
        cut_p = Popen(cut,
                             stdin=tr_p.stdout,
                             stdout=subprocess.PIPE,
                             universal_newlines=True)
        tr_p.stdout.close()

        second_cut = shlex.split("cut -d '/' -f 1")
        if args.verbose >= 2:
            print("Command: [{}]".format(", ".join(map(str, second_cut))))
        second_cut_p = Popen(second_cut,
                             stdin=cut_p.stdout,
                             stdout=subprocess.PIPE,
                             universal_newlines=True)
        cut_p.stdout.close()

        awk = shlex.split("awk 'NR>1{print PREV} {PREV=$0} END{printf(\"%s\",$0)}'")
        if args.verbose >= 2:
            print("Command: [{}]".format(", ".join(map(str, awk))))
        awk_p = Popen(awk,
                             stdin=second_cut_p.stdout,
                             stdout=subprocess.PIPE,
                             universal_newlines=True)
        second_cut_p.stdout.close()

        output = awk_p.communicate()[0]
        if args.verbose >= 1:
            print("Pod '" + name + "' service port: " + output)
        return output


# Get a pod from a list of pods and a name
def get_pod(pods, name):
    return_pod = Pod()
    for pod in pods:
        if pod.name == name:
            return_pod = pod
            break
    assert(return_pod.name != ""), "Pod " + name + " does not exist."
    return return_pod


###############################################################################
# Test utility

# Call subprocess to execute shell command contained in inp
def subprocess_call(inp, lock=None):
    command = shlex.split(inp)
    if args.verbose >= 1:
        if lock is not None:
            lock.acquire()
            try:
                print("Command: [{}]".format(", ".join(map(str, command))))
            finally:
                lock.release()
        else:
            print("Command: [{}]".format(", ".join(map(str, command))))
    process = subprocess.run(command,
                        stdout=subprocess.PIPE,
                        stderr=subprocess.STDOUT,
                        universal_newlines=True)
    output = process.stdout
    if not args.quiet:
        if lock is not None:
            lock.acquire()
            try:
                if args.verbose >= 2:
                    print(output)
            finally:
                lock.release()
        else:
            if args.verbose >= 2:
                print(output)
    return output


# Call subprocess to execute shell command contained in inp, uses custom shell
def subprocess_shell_call(inp, lock=None):
    if args.verbose >= 1:
        if lock is not None:
            lock.acquire()
            try:
                print("Command: [{}]".format(shlex.split("".join(map(str, inp)))))
            finally:
                lock.release()
        else:
            print("Command: [{}]".format(shlex.split("".join(map(str, inp)))))
    process = subprocess.run(inp,
                        stdout=subprocess.PIPE,
                        stderr=subprocess.STDOUT,
                        universal_newlines=True,
                        shell=True)
    output = process.stdout
    if not args.quiet:
        if lock is not None:
            lock.acquire()
            try:
                if args.verbose >= 2:
                    print(output)
            finally:
                lock.release()
        else:
            if args.verbose >= 2:
                print(output)
    return output


# Call subprocess to execute sleep command contained in inp
# Only difference with 'subprocess_call' is that I want to print a message before the command
def sleep_call(inp, lock=None):
    command = shlex.split(inp)
    if args.verbose >= 1:
        if lock is not None:
            lock.acquire()
            try:
                print("Command: [{}]".format(", ".join(map(str, command))))
            finally:
                lock.release()
        else:
            print("Command: [{}]".format(", ".join(map(str, command))))
    if not args.quiet:
        if lock is not None:
            lock.acquire()
            try:
                if args.verbose >= 2:
                    print("Sleeping for " + command[-1] + " seconds...")
            finally:
                lock.release()
        else:
            if args.verbose >= 2:
                print("Sleeping for " + command[-1] + " seconds...")
    process = subprocess.run(command,
                         stdout=subprocess.PIPE,
                         stderr=subprocess.STDOUT,
                         universal_newlines=True)
    output = process.stdout
    return output


# Sends request from src to dst with the specified request_type
def request(src, dst, request_type, lock):
    # Sleeping for 3 seconds before POST
    sleep_call("sleep 2", lock)

    # While capture is running, POST request from owner to adder
    if request_type == "GET":
        subprocess_shell_call("kubectl exec -it " + src.pod_id + " -c workflow-" + src.name + " -- curl --user " + src.name + ":password --header 'Accept: application/json' 'http://" + dst.name + ":" + dst.service_port + "/api/" + dst.name + "' -v", lock)
    else: # POST request
        if dst.name == "owner":
            subprocess_shell_call("kubectl exec -it " + src.pod_id + " -c workflow-" + src.name + " -- curl --user " + src.name + ":password --header 'Content-Type: application/json' --header 'Accept: text/html' -d '{ \"result\": 4 }' 'http://" + dst.name + ":" + dst.service_port + "/api/" + dst.name + "' -v", lock)
        else: # adder or multiplier
            subprocess_shell_call("kubectl exec -it " + src.pod_id + " -c workflow-" + src.name + " -- curl --user " + src.name + ":password --header 'Content-Type: application/json' --header 'Accept: text/html' -d '{ \"first_number\": 4, \"second_number\": 2 }' 'http://" + dst.name + ":" + dst.service_port + "/api/" + dst.name + "' -v", lock)


# Launches a packet capture, a request and fetches the capture file
# src, dst and capture_pod are Pod()
def request_capture(src, dst, request_type, capture_pod, interface): #TODO Fix parallel display
    # Set filename for packet capture
    capture_file = args.capture_dir + src.name + "-" + dst.name + "-" + request_type + "-" + capture_pod.name + "-" + interface + ".pcap"

    # Lock for parallel processing access to output
    lock = Lock()

    # Start capturing on the eth0 interface of the tcpdump container of the owner pod
    # -G SECONDS -W 1 : Run for SECONDS seconds
    # -w FILE : specify the dump file
    # -i INTERFACE : specify the interface
    capture_p = Process(target=subprocess_shell_call, args=("kubectl exec -it " + capture_pod.pod_id + " -c tcpdump -- tcpdump -G 5 -W 1 -w /tmp/capture.pcap -i " + interface, lock))

    # Sends request
    request_p = Process(target=request, args=(src, dst, request_type, lock))

    # Start parallel capture and request
    capture_p.start()
    request_p.start()

    # Wait for both processes
    capture_p.join()
    request_p.join()

    # Copy capture to host machine
    subprocess_shell_call("kubectl cp " + capture_pod.pod_id + ":/tmp/capture.pcap -c tcpdump " + capture_file)


# Identify the capture to determine what to look for
# src.lo and dst.lo should display HTTP
# src.eth0 and dst.eth0 should display TLS
# bystander.lo and bystander.eth0 should display nothing
def id_capture(capture):
    # Unpack items
    capture_items = capture.split('.')[0].split('/')[-1].split('-')
    capture_src, capture_dst, capture_request_type, capture_pod, interface = capture_items

    if args.verbose >= 2:
        print(capture_src, capture_dst, capture_request_type, capture_pod, interface)

    # Return variable
    return_code = ""

    if capture_pod == capture_src and interface == "lo":
        return_code = "SRC_LO"
    elif capture_pod == capture_dst and interface == "lo":
        return_code = "DST_LO"
    elif capture_pod == capture_src and interface == "eth0":
        return_code = "SRC_ETH0"
    elif capture_pod == capture_dst and interface == "eth0":
        return_code = "DST_ETH0"
    elif capture_pod != capture_src and capture_pod != capture_dst and interface == "lo":
        return_code = "BYSTANDER_LO"
    elif capture_pod != capture_src and capture_pod != capture_dst and interface == "eth0":
        return_code = "BYSTANDER_ETH0"

    assert(return_code != ""), "The identity of capture " + capture + " could not be established."

    if args.verbose >= 1:
        print("Capture " + capture + ": " + return_code)
    return return_code


# According to the capture and the ID, check if policy is enforced
def check_capture(capture, capture_id, authorization, pods):
    # Capture does not exist
    if not os.path.isfile(capture):
        print('"{}" does not exist'.format(capture), file=sys.stderr)
        terminate_app(-1)

    # Unpack items from capture filename
    capture_items = capture.split('.')[0].split('/')[-1].split('-')
    capture_src, capture_dst, capture_request_type, capture_pod, interface = capture_items
    capture_src_pod = get_pod(pods, capture_src)
    capture_dst_pod = get_pod(pods, capture_dst)
    capture_cap_pod = get_pod(pods, capture_pod)
    if args.verbose >= 2:
        print(capture_src, capture_dst, capture_request_type, capture_pod, interface)

    # Open capture file with scapy
    if args.verbose >= 1:
        print("Opening {}...".format(capture))
    scapy_capture = rdpcap(capture)

    # Get sessions
    sessions = scapy_capture.sessions()
    if args.verbose >= 1:
        pprint.pprint(sessions)

    # Capturing was done on the source loopback
    if capture_id == "SRC_LO":
        # Flags for finding relevant sessions
        found_src_dst_flow = False
        found_dst_src_flow = False

        # Error handling
        found_request_type = False

        # Return value
        return_check = ""

        # Find the relevant sessions in the capture
        for session in sessions:
            if args.verbose >= 1:
                print(session)

            # Unpack items from session
            session_chunks = session.split(' ')
            session_src = session_chunks[1]
            session_dst = session_chunks[3]

            # Relevant session: Source -> Destination
            if session_src.split(':')[0] == capture_src_pod.pod_ip and session_dst == "127.0.0.1:15001":
                # Found relevant session from source to destination
                found_src_dst_flow = True
                if args.verbose >= 2:
                    print("Found SRC -> DST")

                for packet in sessions[session]:
                    if Raw in packet:
                        # Extract HTTP payload
                        payload = packet[Raw].load.decode()
                        if args.verbose >= 2:
                            print(payload)

                        # Check request type is consistent with expectations
                        if capture_request_type in payload:
                            found_request_type = True

                # Request type was not consistent with expectations
                if not found_request_type:
                    raise ValueError("Capture " + capture + ": Request type " + capture_request_type + " inconsistent with expectations.")

            # Relevant session: Destination -> Source
            elif session_src == capture_dst_pod.service_ip + ':' + capture_dst_pod.service_port and session_dst.split(':')[0] == capture_src_pod.pod_ip:
                # Found relevant session from destination to source
                found_dst_src_flow = True
                if args.verbose >= 2:
                    print("Found DST -> SRC")

                for packet in sessions[session]:
                    if Raw in packet:
                        # Extract HTTP payload
                        payload = packet[Raw].load.decode()
                        if args.verbose >= 2:
                            print(payload)

                        # Check response type
                        response_type = payload.splitlines()[0]
                        if args.verbose >= 2:
                            print("Capture response type: " + response_type)

                        # The request was a GET
                        if capture_request_type == "GET":
                            # Request was authorized
                            if response_type ==  "HTTP/1.1 200 OK":
                                if args.verbose >= 2:
                                    print("Request was allowed.")
                                if authorization == "allow":
                                    return_check = "OK"
                                else:
                                    return_check = "KO"

                            # Request was denied
                            elif response_type == "HTTP/1.1 403 Forbidden":
                                if args.verbose >= 2:
                                    print("Request was denied.")
                                if authorization == "deny":
                                    return_check = "OK"
                                else:
                                    return_check = "KO"


                        # The request was a POST
                        elif capture_request_type == "POST":
                            # Request was authorized
                            if response_type == "HTTP/1.1 201 Created":
                                if args.verbose >= 2:
                                    print("Request was allowed.")
                                if authorization == "allow":
                                    return_check = "OK"
                                else:
                                    return_check = "KO"

                            # Request was denied
                            elif response_type == "HTTP/1.1 403 Forbidden":
                                if args.verbose >= 2:
                                    print("Request was denied.")
                                if authorization == "deny":
                                    return_check = "OK"
                                else:
                                    return_check = "KO"

                        else:
                            raise ValueError("Capture " + capture + ": Unrecognized response type " + response_type + ".")

        # No relevant session found
        if not found_src_dst_flow or not found_dst_src_flow:
            raise ValueError("Capture " + capture + ": Missing matching session.")
        # TODO: Make more fine-grained tests to see if both sessions, or only one was missing

        assert(return_check != ""), "Return check was never determined."
        return return_check


    # Capturing was done on the destination loopback
    elif capture_id == "DST_LO" and authorization == "allow":
        # Flags for finding relevant sessions
        found_src_dst_flow = False
        found_dst_src_flow = False

        # Error handling
        found_request_type = False

        # Return value
        return_check = ""

        # Find the relevant sessions in the capture
        for session in sessions:
            if args.verbose >= 1:
                print(session)

            # Unpack items from session
            session_chunks = session.split(' ')
            session_src = session_chunks[1]
            session_dst = session_chunks[3]

            # Relevant session: Source -> Destination
            if session_src.split(':')[0] == "127.0.0.1" and session_dst == "127.0.0.1:" + capture_dst_pod.service_port:
                # Found relevant session from source to destination
                found_src_dst_flow = True
                if args.verbose >= 2:
                    print("Found SRC -> DST")

                for packet in sessions[session]:
                    if Raw in packet:
                        # Extract HTTP payload
                        payload = packet[Raw].load.decode()
                        if args.verbose >= 2:
                            print(payload)

                        # Check request type is consistent with expectations
                        if capture_request_type in payload:
                            found_request_type = True

                # Request type was not consistent with expectations
                if not found_request_type:
                    raise ValueError("Capture " + capture + ": Request type " + capture_request_type + " inconsistent with expectations.")

            # Relevant session: Destination -> Source
            elif session_src == "127.0.0.1:" + capture_dst_pod.service_port and session_dst.split(':')[0] == "127.0.0.1":
                # Found relevant session from destination to source
                found_dst_src_flow = True
                if args.verbose >= 2:
                    print("Found DST -> SRC")

                for packet in sessions[session]:
                    if Raw in packet:
                        # Extract HTTP payload
                        payload = packet[Raw].load.decode()
                        if args.verbose >= 2:
                            print(payload)

                        # Check response type
                        response_type = payload.splitlines()[0]
                        if args.verbose >= 2:
                            print("Capture response type: " + response_type)

                        # The request was a GET
                        if capture_request_type == "GET":
                            # Request was authorized
                            if response_type ==  "HTTP/1.0 200 OK":
                                if args.verbose >= 2:
                                    print("Request was allowed.")
                                if authorization == "allow":
                                    return_check = "OK"
                                else:
                                    return_check = "KO"

                            # Request was denied
                            elif response_type == "HTTP/1.1 403 Forbidden":
                                if args.verbose >= 2:
                                    print("Request was denied.")
                                if authorization == "deny":
                                    return_check = "OK"
                                else:
                                    return_check = "KO"

                        # The request was a POST
                        elif capture_request_type == "POST":
                            # Request was authorized
                            if response_type == "HTTP/1.0 201 CREATED":
                                if args.verbose >= 2:
                                    print("Request was allowed.")
                                if authorization == "allow":
                                    return_check = "OK"
                                else:
                                    return_check = "KO"

                            # Request was denied
                            elif response_type == "HTTP/1.1 403 Forbidden":
                                if args.verbose >= 2:
                                    print("Request was denied.")
                                if authorization == "deny":
                                    return_check = "OK"
                                else:
                                    return_check = "KO"

                        else:
                            raise ValueError("Capture " + capture + ": Unrecognized response type " + response_type + ".")

        # No relevant session found
        if not found_src_dst_flow or not found_dst_src_flow:
            raise ValueError("Capture " + capture + ": Missing matching session.")
        # TODO: Make more fine-grained tests to see if both sessions, or only one was missing

        assert(return_check != ""), "Return check was never determined."
        return return_check


    # Capturing was done on the source/destination external interface
    elif capture_id == "SRC_ETH0" or capture_id == "DST_ETH0":
        # Flags for finding relevant sessions
        found_src_dst_flow = False
        found_dst_src_flow = False
        found_cleartext = False

        # Return value
        return_check = ""

        # Find the relevant sessions in the capture
        for session in sessions:
            if args.verbose >= 1:
                print(session)

            # Unpack items from session
            session_chunks = session.split(' ')
            session_src = session_chunks[1]
            session_dst = session_chunks[3]

            # Relevant session: Source -> Destination
            if session_src.split(':')[0] == capture_src_pod.pod_ip and session_dst == capture_dst_pod.pod_ip + ':' + capture_dst_pod.service_port:
                # Found relevant session from source to destination
                found_src_dst_flow = True
                if args.verbose >= 2:
                    print("Found SRC -> DST")

                for packet in sessions[session]:
                    if Raw in packet:
                        try:
                            payload = packet[Raw].load.decode()
                            found_cleartext = True
                        except:
                            if args.verbose >= 2:
                                print("No cleartext here...")

                if found_cleartext:
                    return_check = "KO"
                else:
                    return_check = "OK"

            # Relevant session: Destination -> Source
            elif session_src == capture_dst_pod.pod_ip + ':' + capture_dst_pod.service_port and session_dst.split(':')[0] == capture_src_pod.pod_ip:
                # Found relevant session from destination to source
                found_dst_src_flow = True
                if args.verbose >= 2:
                    print("Found DST -> SRC")

                for packet in sessions[session]:
                    if Raw in packet:
                        try:
                            payload = packet[Raw].load.decode()
                            found_cleartext = True
                        except:
                            if args.verbose >= 2:
                                print("No cleartext here...")

                if found_cleartext:
                    return_check = "KO"
                else:
                    return_check = "OK"

        # No relevant session found
        if not found_src_dst_flow or not found_dst_src_flow:
            raise ValueError("Capture " + capture + ": Missing matching session.")
        # TODO: Make more fine-grained tests to see if both sessions, or only one was missing

        assert(return_check != ""), "Return check was never determined."
        return return_check


    # Capturing was done on a bystander or capturing was done on the destination loopback and the policy is "deny"
    elif capture_id == "BYSTANDER_LO" or capture_id == "BYSTANDER_ETH0" or (capture_id == "DST_LO" and authorization == "deny"):
        # Flags for finding relevant sessions
        found_src_dst_flow = False
        found_dst_src_flow = False

        # Return value
        return_check = ""

        # Find the relevant sessions in the capture
        for session in sessions:
            if args.verbose >= 1:
                print(session)

            # Unpack items from session
            session_chunks = session.split(' ')
            session_src = session_chunks[1]
            session_dst = session_chunks[3]

            # Relevant session: Source -> Destination
            if session_src.split(':')[0] == capture_src_pod.pod_ip and session_dst == capture_dst_pod.pod_ip + ':' + capture_dst_pod.service_port:
                # Found relevant session from source to destination
                found_src_dst_flow = True
                if args.verbose >= 2:
                    print("Found SRC -> DST")

            # Relevant session: Destination -> Source
            elif session_src == capture_dst_pod.pod_ip + ':' + capture_dst_pod.service_port and session_dst.split(':')[0] == capture_src_pod.pod_ip:
                # Found relevant session from destination to source
                found_dst_src_flow = True
                if args.verbose >= 2:
                    print("Found DST -> SRC")

        # No relevant session found
        if not found_src_dst_flow and not found_dst_src_flow:
            return_check = "OK"
        else:
            return_check = "KO"

        assert(return_check != ""), "Return check was never determined."
        return return_check

    else:
        raise ValueError("Capture " + capture + ": Capture ID " + capture_id + " not valid.")


###############################################################################
# Main

#TODO Python doc string
if __name__ == "__main__":
    # Create a parser
    parser = get_parser()

    # Parse arguments
    args = parser.parse_args()

    if not args.quiet:
        print(args)

    # Skip this if Kubernetes already initialized
    if args.start:
        # Start minikube
        subprocess_call("minikube start --memory=8192 --cpus=4")

        # Wait for minikube to be ready
        sleep_call("sleep 30")

        # Delete all workflow pods
        subprocess_call("kubectl delete --all pods --namespace=default")

        # Wait for pods to be ready for demo
        sleep_call("sleep 30")


    services = ["owner", "adder", "multiplier"] # services in default namespace
    request_types = ["GET", "POST"] # Possible requests
    interfaces = ["lo", "eth0"] # Possible interfaces
    pods = [Pod(service) for service in services] # pods in default namespace
    if args.override_pods:
        pod_ip_overrides = [i.split(':') for i in args.override_pods.split(", ")]
        for override_pod, override_ip in pod_ip_overrides:
            for pod in pods:
                if pod.name == override_pod:
                    pod.pod_ip = override_ip
    if args.no_capture:
        with open("capture-metadata.dat") as capture_metadata:
            for line in capture_metadata:
                pod_chunks = line.split(')')[0].split('(')[-1].split(", ")
                for pod in pods:
                    if pod.name == pod_chunks[0]:
                        pod.pod_ip = pod_chunks[2]
    if not args.quiet:
        for pod in pods:
            print(pod)


    # Packet capture
    if not args.no_capture:
        # Capture metadata file
        with open("capture-metadata.dat", "w+") as capture_metadata:
            for pod in pods:
                capture_metadata.write(repr(pod))
                capture_metadata.write("\n")

        # For each possible communication, capture on each possible interface
        print("Capturing packets...")
        for src in pods:
            for dst in pods:
                if src != dst:
                    for request_type in request_types:
                        for capture_pod in pods:
                            for interface in interfaces:
                                request_capture(src, dst, request_type, capture_pod, interface)


    # Fetch policy from YAML configuration file and store it in policy
    with open(args.policy_file) as policy_file:
        # Isolate the opa-policy section
        policy = policy_file.read().split("name: opa-policy")[-1]
        if args.verbose >= 1:
            print(policy)


    # Get the default allow policy
    default_allow = ""
    for line in policy.split('\n'):
        if "default allow" in line:
            default_allow = line.split('=')[1].lstrip(' ')
    assert(default_allow != ""), "A default policy must be defined."

    if args.verbose >= 1:
        print("default allow = " + default_allow)


    # Fill authorized_comms with the default policy
    if default_allow == "true":
        authorized_comms = {src: {dst: {request_type: "allow" for request_type in request_types} for dst in pods if src != dst} for src in pods}
    else:
        authorized_comms = {src: {dst: {request_type: "deny" for request_type in request_types} for dst in pods if src != dst} for src in pods}

    # Get role permissions from policy as a dictionary
    role_perms = literal_eval(policy.split("role_perms = ")[1])
    if args.verbose >= 1:
        pprint.pprint(role_perms)

    # According to the rest of the policy, change authorized_comms values needing change
    for src in role_perms:
        for comm in role_perms[src]:
            dst = comm["path"].split('/')[-1]
            request_type = comm["method"]
            if args.verbose >= 1:
                print("Modifying permission: " + src, dst, request_type)
            authorized_comms[get_pod(pods, src)][get_pod(pods, dst)][request_type] = "allow"

    if not args.quiet:
        pprint.pprint(authorized_comms)


    # Check capture files to confirm or infirm policy is enforced
    # For each possible communication in authorized_comms
    for communication in authorized_comms:
        # Get all relevant packet captures
        for src in authorized_comms:
            for dst in authorized_comms[src]:
                for request_type in authorized_comms[src][dst]:
                    # Pattern to match
                    pattern = src.name + "-" + dst.name + "-" + request_type + ".*\.pcap"
                    if args.verbose >= 1:
                        print(pattern)

                    # Captures like: "{src}-{dst}-{request_type}*.pcap"
                    captures = [args.capture_dir + capture for capture in os.listdir(args.capture_dir) if re.match(pattern, capture)]
                    if args.verbose >= 2:
                        print(captures)

                    print("{:10s}  {:11s}  {:4s}  {:14s}  {:6s}  {}".format("SOURCE", "DESTINATION", "TYPE", "CAPTURE", "POLICY", "CHECK"))
                    for capture in captures:
                        # Identify the capture to determine what to look for
                        capture_id = id_capture(capture)

                        # According to the capture and the ID, check if policy is enforced
                        check = check_capture(capture, capture_id, authorized_comms[src][dst][request_type], pods)
                        print("{:10s}  {:11s}  {:4s}  {:14s}  {:6s}  {}".format(src.name, dst.name, request_type, capture_id, authorized_comms[src][dst][request_type], check))

                        # TODO: If all captures for this comm are OK, put green edge on graph, else red edge
                        # This needs to create a full edge graph between services nodes
                    print("\n")


    # Stop Kubernetes after the tests
    if args.kill:
        # Stop minikube
        subprocess_call("minikube stop")

    terminate_app(0)


###############################################################################
