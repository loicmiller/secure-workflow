"""
This is the document module and supports REST actions
"""

# System modules
from datetime import datetime

# 3rd party modules
from flask import make_response, abort


def get_timestamp():
    return datetime.now().strftime(("%Y-%m-%d %H:%M:%S"))

def get_document(document_name):
    """
    This function responds to a request for /api/document-base
    with the patient's records
    :return:        pdf document
    """
    # Create the list of people from our data
    with open(document_name, "r") as f:
        return f.read()

def post_document(documents):
    """
    This function responds to a request for /api/document-base
    with the patient's records
    :return:        pdf document
    """
    document_name = documents.get("document_name", None)
    document = documents.get("document", None)

    with open(document_name, "a") as f:
        f.write(document)

    return make_response("{} successfully created\n".format(document_name), 201)
