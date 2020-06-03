"""
This is the number module and supports REST actions for the
NUMBERS collection
"""

# System modules
from datetime import datetime

# 3rd party modules
from flask import make_response, abort


def get_timestamp():
    return datetime.now().strftime(("%Y-%m-%d %H:%M:%S"))


# Data to serve with our API
NUMBERS = {
    get_timestamp(): {
        "first_number": "1",
        "second_number": "2",
        "sum": "3",
        "timestamp": get_timestamp(),
    },
}

def read_all():
    """
    This function responds to a request for /api/adder
    with the complete lists of numbers
    :return:        json string of list of numbers
    """
    # Create the list of people from our data
    return [NUMBERS[key] for key in sorted(NUMBERS.keys())]

def sum(numbers):
    """
    This function creates a new sum in the numbers structure
    based on the passed in numbers data

    :param numbers:  numbers to create in numbers structure
    :return:        201 on success
    """
    numb1 = numbers.get("first_number", None)
    numb2 = numbers.get("second_number", None)

    sum = numb1 + numb2

    NUMBERS[get_timestamp()] = {
        "first_number": numb1,
        "second_number": numb2,
        "sum": sum,
        "timestamp": get_timestamp(),
    }

    return make_response("{sum} successfully created".format(sum=sum), 201)
