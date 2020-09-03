###############################################################################
# Imports

import sys # Exit function
import os # OS functions
import argparse # Argument parser
import pprint # Pretty printing dicts
from datetime import datetime # Dates

# Shell commands
import subprocess
from subprocess import Popen,PIPE
import shlex # Shell command parsing

from ast import literal_eval # String to dictionary
import re # Regular expressions

import json # Get transition times


###############################################################################
# General utility and variables

#contexts = get_contexts()
contexts = ["owner", "vfx", "color", "sound", "hdr"]
services = ["owner", "vfx1", "vfx2", "vfx3", "color", "sound", "hdr"] # workflow services

number_of_measures = 800 # Number of measures to realize


# Returns the contexts of the multi-cluster
def get_contexts():
    contexts = shlex.split("kubectx")
    if args.verbose >= 2:
        print("Command: [{}]".format(", ".join(map(str, get_pods))))
    contexts_p = Popen(contexts,
                         stdout=subprocess.PIPE,
                         universal_newlines=True)

    stdout = contexts_p.communicate()
    if args.verbose >= 2:
        print(stdout)

    return stdout


# Returns pods available in a given context
def get_pods(context):
    get_pods = shlex.split("kubectl --context {} get pods -o wide".format(context))
    if args.verbose >= 3:
        print("Command: [{}]".format(", ".join(map(str, get_pods))))
    get_pods_p = Popen(get_pods,
                         stdout=subprocess.PIPE,
                         universal_newlines=True)

    tr = shlex.split("tr -s ' '")
    if args.verbose >= 3:
        print("Command: [{}]".format(", ".join(map(str, tr))))
    tr_p = Popen(tr,
                         stdin=get_pods_p.stdout,
                         stdout=subprocess.PIPE,
                         universal_newlines=True)
    get_pods_p.stdout.close()

    stdout = tr_p.communicate()
    if args.verbose >= 2:
        print(stdout)

    stdout_pods = stdout[0].split('\n')[1:-1]
    pods = []
    for line in stdout_pods:
        if args.verbose >= 2:
            print("Line: {}".format(line))
        pod_id = line.split()[0]
        pod_name = pod_id.split('-v1')[0]
        pods.append(pod_name)

    if args.verbose >= 2:
        print(pods)

    return pods


# Returns a pod from a list of pods and a name
def get_pod(pods, name):
    return_pod = Pod()
    for pod in pods:
        if pod.name == name:
            return_pod = pod
            break
    assert(return_pod.name != ""), "Pod " + name + " does not exist."
    return return_pod


def get_startup_time(pod):
    get_pod = shlex.split("kubectl --context {} get pod -o json {}".format(pod.context, pod.pod_id))
    if args.verbose >= 3:
        print("Command: [{}]".format(", ".join(map(str, get_pod))))
    get_pod_p = Popen(get_pod,
                         stdout=subprocess.PIPE,
                         universal_newlines=True)

    stdout = get_pod_p.communicate()

    pod_scheduled_transition_time = ""
    initialized_transition_time = ""
    containers_ready_transition_time = ""
    ready_transition_time = ""

    command_output = json.loads(stdout[0])
    if args.verbose >= 3:
        print(command_output["status"]["conditions"])
    for status in command_output["status"]["conditions"]:
        if args.verbose >= 2:
            print(status)

        if status["type"] == 'PodScheduled':
            pod_scheduled_transition_time = status["lastTransitionTime"]
        elif status["type"] == 'Initialized':
            initialized_transition_time = status["lastTransitionTime"]
        elif status["type"] == 'ContainersReady':
            containers_ready_transition_time = status["lastTransitionTime"]
        elif status["type"] == 'Ready':
            ready_transition_time = status["lastTransitionTime"]
        else:
            print("ERR: Unknown status")
            terminate_app(0)

    ready_dt = datetime.strptime(ready_transition_time, "%Y-%m-%dT%H:%M:%SZ")
    pod_scheduled_dt = datetime.strptime(pod_scheduled_transition_time, "%Y-%m-%dT%H:%M:%SZ")
    startup_time = (ready_dt - pod_scheduled_dt).total_seconds()

    pod.transition_times.append((pod.name, pod_scheduled_transition_time, initialized_transition_time, containers_ready_transition_time, ready_transition_time, startup_time))

    return pod.transition_times[-1]


def delete_pod(pod):
    delete_pod = shlex.split("kubectl --context {} delete pod {}".format(pod.context, pod.pod_id))
    if args.verbose >= 3:
        print("Command: [{}]".format(", ".join(map(str, delete_pod))))
    delete_pod_p = Popen(delete_pod,
                         stdout=subprocess.PIPE,
                         universal_newlines=True)

    stdout = delete_pod_p.communicate()
    if args.verbose >= 2:
        print(stdout)


def update_pod(pods, pod_to_update):
    updated_pod = Pod(pod_to_update.name, pod_to_update.context)
    updated_pod.transition_times = pod_to_update.transition_times

    for i, pod in enumerate(pods):
        if pod.name == updated_pod.name:
            pods[i] = updated_pod



# Exit the program
def terminate_app(code):
    print("Exiting program...")
    sys.exit(code)


###############################################################################
# Argument parser

def get_parser():
    # Get parser for command line arguments
    parser = argparse.ArgumentParser(description="Measures for secure architecture", formatter_class=argparse.ArgumentDefaultsHelpFormatter)
    parser.add_argument("--version", action="version", version='%(prog)s 1.0')
    parser.add_argument("-v", "--verbose", action="count", default=0, help="increase output verbosity")
    parser.add_argument("-o", "--output-file", type=str, metavar="FILE", default="startup-time.dat", help="file to store measurements")

    return parser


###############################################################################
# Pod object

class Pod:
    def __init__(self, name=None, context=None):
        # Dummy pod for error handling
        if name is None:
            self.name = ""
            self.context = ""
            self.pod_id = ""
            self.pod_ip = ""
            self.service_ip = ""
            self.service_port = ""
            self.transition_times = []
        else:
            self.name = name
            self.context = context
            assert(self.context != None), "Pod " + name + " has no context."
            self.pod_id = self.get_pod_id(name, context)
            assert(self.pod_id != ""), "Pod " + name + " does not exist."
            self.pod_ip = self.get_pod_ip(name, context)
            assert(self.pod_ip != ""), "Pod " + name + " has no IP."
            self.service_ip = self.get_service_ip(name, context)
            assert(self.service_ip != ""), "Pod " + name + " has no service IP."
            self.service_port = self.get_service_port(name, context)
            assert(self.service_port != ""), "Pod " + name + " has no service port."
            self.transition_times = []

    def __repr__(self):
        return "Pod({}, {}, {}, {}, {}, {})".format(self.name, self.context, self.pod_id, self.pod_ip, self.service_ip, self.service_port)

    # Returns the pod ID
    def get_pod_id(self, name, context):
        get_pods = shlex.split("kubectl --context {} get pods".format(context))
        if args.verbose >= 3:
            print("Command: [{}]".format(", ".join(map(str, get_pods))))
        get_pods_p = Popen(get_pods,
                             stdout=subprocess.PIPE,
                             universal_newlines=True)

        grep = shlex.split("grep " + name)
        if args.verbose >= 3:
            print("Command: [{}]".format(", ".join(map(str, grep))))
        grep_p = Popen(grep,
                             stdin=get_pods_p.stdout,
                             stdout=subprocess.PIPE,
                             universal_newlines=True)
        get_pods_p.stdout.close()

        tr = shlex.split("tr -s ' '")
        if args.verbose >= 3:
            print("Command: [{}]".format(", ".join(map(str, tr))))
        tr_p = Popen(tr,
                             stdin=grep_p.stdout,
                             stdout=subprocess.PIPE,
                             universal_newlines=True)
        grep_p.stdout.close()

        cut = shlex.split("cut -d ' ' -f 1")
        if args.verbose >= 3:
            print("Command: [{}]".format(", ".join(map(str, cut))))
        cut_p = Popen(cut,
                             stdin=tr_p.stdout,
                             stdout=subprocess.PIPE,
                             universal_newlines=True)
        tr_p.stdout.close()

        awk = shlex.split("awk 'NR>1{print PREV} {PREV=$0} END{printf(\"%s\",$0)}'")
        if args.verbose >= 3:
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
    def get_pod_ip(self, name, context):
        get_pods = shlex.split("kubectl --context {} get pods -o wide".format(context))
        if args.verbose >= 3:
            print("Command: [{}]".format(", ".join(map(str, get_pods))))
        get_pods_p = Popen(get_pods,
                             stdout=subprocess.PIPE,
                             universal_newlines=True)

        grep = shlex.split("grep " + name)
        if args.verbose >= 3:
            print("Command: [{}]".format(", ".join(map(str, grep))))
        grep_p = Popen(grep,
                             stdin=get_pods_p.stdout,
                             stdout=subprocess.PIPE,
                             universal_newlines=True)
        get_pods_p.stdout.close()

        tr = shlex.split("tr -s ' '")
        if args.verbose >= 3:
            print("Command: [{}]".format(", ".join(map(str, tr))))
        tr_p = Popen(tr,
                             stdin=grep_p.stdout,
                             stdout=subprocess.PIPE,
                             universal_newlines=True)
        grep_p.stdout.close()

        cut = shlex.split("cut -d ' ' -f 6")
        if args.verbose >= 3:
            print("Command: [{}]".format(", ".join(map(str, cut))))
        cut_p = Popen(cut,
                             stdin=tr_p.stdout,
                             stdout=subprocess.PIPE,
                             universal_newlines=True)
        tr_p.stdout.close()

        awk = shlex.split("awk 'NR>1{print PREV} {PREV=$0} END{printf(\"%s\",$0)}'")
        if args.verbose >= 3:
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


    # Returns the IP of the service
    def get_service_ip(self, name, context):
        # kubectl get services | grep "adder" | tr -s ' ' | cut -d ' ' -f 5 | cut -d '/' -f 1
        get_services = shlex.split("kubectl --context {} get services".format(context))
        if args.verbose >= 3:
            print("Command: [{}]".format(", ".join(map(str, get_services))))
        get_services_p = Popen(get_services,
                             stdout=subprocess.PIPE,
                             universal_newlines=True)

        grep = shlex.split("grep " + name)
        if args.verbose >= 3:
            print("Command: [{}]".format(", ".join(map(str, grep))))
        grep_p = Popen(grep,
                             stdin=get_services_p.stdout,
                             stdout=subprocess.PIPE,
                             universal_newlines=True)
        get_services_p.stdout.close()

        tr = shlex.split("tr -s ' '")
        if args.verbose >= 3:
            print("Command: [{}]".format(", ".join(map(str, tr))))
        tr_p = Popen(tr,
                             stdin=grep_p.stdout,
                             stdout=subprocess.PIPE,
                             universal_newlines=True)
        grep_p.stdout.close()

        cut = shlex.split("cut -d ' ' -f 3")
        if args.verbose >= 3:
            print("Command: [{}]".format(", ".join(map(str, cut))))
        cut_p = Popen(cut,
                             stdin=tr_p.stdout,
                             stdout=subprocess.PIPE,
                             universal_newlines=True)
        tr_p.stdout.close()

        awk = shlex.split("awk 'NR>1{print PREV} {PREV=$0} END{printf(\"%s\",$0)}'")
        if args.verbose >= 3:
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


    # Returns the port number of the service
    def get_service_port(self, name, context):
        # kubectl get services | grep "adder" | tr -s ' ' | cut -d ' ' -f 5 | cut -d '/' -f 1
        get_services = shlex.split("kubectl --context {} get services".format(context))
        if args.verbose >= 3:
            print("Command: [{}]".format(", ".join(map(str, get_services))))
        get_services_p = Popen(get_services,
                             stdout=subprocess.PIPE,
                             universal_newlines=True)

        grep = shlex.split("grep " + name)
        if args.verbose >= 3:
            print("Command: [{}]".format(", ".join(map(str, grep))))
        grep_p = Popen(grep,
                             stdin=get_services_p.stdout,
                             stdout=subprocess.PIPE,
                             universal_newlines=True)
        get_services_p.stdout.close()

        tr = shlex.split("tr -s ' '")
        if args.verbose >= 3:
            print("Command: [{}]".format(", ".join(map(str, tr))))
        tr_p = Popen(tr,
                             stdin=grep_p.stdout,
                             stdout=subprocess.PIPE,
                             universal_newlines=True)
        grep_p.stdout.close()

        cut = shlex.split("cut -d ' ' -f 5")
        if args.verbose >= 3:
            print("Command: [{}]".format(", ".join(map(str, cut))))
        cut_p = Popen(cut,
                             stdin=tr_p.stdout,
                             stdout=subprocess.PIPE,
                             universal_newlines=True)
        tr_p.stdout.close()

        second_cut = shlex.split("cut -d '/' -f 1")
        if args.verbose >= 3:
            print("Command: [{}]".format(", ".join(map(str, second_cut))))
        second_cut_p = Popen(second_cut,
                             stdin=cut_p.stdout,
                             stdout=subprocess.PIPE,
                             universal_newlines=True)
        cut_p.stdout.close()

        awk = shlex.split("awk 'NR>1{print PREV} {PREV=$0} END{printf(\"%s\",$0)}'")
        if args.verbose >= 3:
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


###############################################################################
# Main

#TODO Python doc string
if __name__ == "__main__":
    print("\n\n###############################################################################")
    print("Getting arguments")
    print("###############################################################################")
    # Create a parser
    parser = get_parser()

    # Parse arguments
    args = parser.parse_args()

    print(args)


    print("\n\n###############################################################################")
    print("Creating pod objects")
    print("###############################################################################")
    # Create pod objects
    pods = []
    for context in contexts:
        context_pods = get_pods(context)
        for pod in context_pods:
            pods.append(Pod(pod, context))

    for pod in pods:
        print(pod)


    print("\n\n###############################################################################")
    print("Getting measurements")
    print("###############################################################################")
    # Get measurements
    for measure in range(number_of_measures):
        print("\n############################## Measure number {} ##############################".format(measure))
        for pod in pods:
            print("\n################################### Pod {} ###################################".format(pod.name))
            last_pod_tuple = get_startup_time(pod)
            with open(args.output_file, 'a+') as f:
                f.write(str(last_pod_tuple) + "\n")
            delete_pod(pod)
            update_pod(pods, pod)


    if args.verbose >= 2:
        print("\n\n###############################################################################")
        print("Printing measurements")
        print("###############################################################################")
        for pod in pods:
            print(pod.transition_times)


    print("\n\n###############################################################################")
    print("Storing measurements")
    print("###############################################################################")
    # Store measurements
    #with open(args.output_file, 'a+') as f:
    #    for pod in pods:
    #        for line in pod.transition_times:
    #            f.write(str(line) + "\n")

    terminate_app(0)


###############################################################################
