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
        "result": "1",
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

def store(number):
    """
    This function creates a new result in the numbers structure
    based on the passed in numbers data

    :param numbers:  numbers to create in numbers structure
    :return:        201 on success
    """
    result = number.get("result", None)


    NUMBERS[get_timestamp()] = {
        "result": result,
        "timestamp": get_timestamp(),
    }

    return make_response("{result} successfully created".format(result=result), 201)
