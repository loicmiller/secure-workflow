###############################################################################
# Imports

import sys
import argparse # Argument parser

from random import randrange


###############################################################################
# General utility

# Exit the program
def terminate_app(code):
    print("Exiting program...")
    sys.exit(code)


###############################################################################
# Argument parser

def get_parser():
    # Get parser for command line arguments
    parser = argparse.ArgumentParser(description="Workflow Metagraph Generator", formatter_class=argparse.ArgumentDefaultsHelpFormatter)
    parser.add_argument("--version", action="version", version='%(prog)s 1.0')
    parser.add_argument("-v", "--verbose", action="count", default=0, help="increase output verbosity")
    parser.add_argument("policy", type=str, metavar="POLICY", help="policy to modify")
    parser.add_argument("-n", "--number_of_rules", type=int, default=10, metavar="RULES_NUMBER", help="number of rules to add")

    return parser


###############################################################################
# Functions
def random_rule(rules):
    return rules[randrange(len(rules))]


###############################################################################
# Main

if __name__ == '__main__':
    print("\n\n###############################################################################")
    print("Getting arguments")
    print("###############################################################################")

    parser = get_parser() # Create a parser
    args = parser.parse_args() # Parse arguments
    print(args)

    print("\n\n###############################################################################")
    print("Loading policy")
    print("###############################################################################")

    # Load policy
    with open(args.policy, 'r') as input_policy:
        policy = input_policy.readlines()

    # Generate output policy name
    output_policy_name = "bulked-up-policies/" + args.policy.split('.')[0].split('/')[-1] + "-bulked-up-" + str(args.number_of_rules) + ".rego"
    print("Output policy file: {}".format(output_policy_name))


    print("\n\n###############################################################################")
    print("Bulking policy")
    print("###############################################################################")

    # Insert code in allows
    with open(output_policy_name, 'w') as output_policy:
        for line in policy:
            if line == "allow {\n":
                line = line + "  performance_hit\n"
            output_policy.write(line)

    # Insert evaluations of function
    rules = ["1 < 2", "2 < 3", "3 < 4"] # rules in body
    performance_hit = []
    performance_hit.append("performance_hit {\n")
    for i in range(args.number_of_rules):
        print(i)
        performance_hit.append("  {}\n".format(random_rule(rules)))
    performance_hit.append("}\n")

    with open(output_policy_name, 'a') as output_policy:
        output_policy.writelines(performance_hit)


    terminate_app(0)


###############################################################################
