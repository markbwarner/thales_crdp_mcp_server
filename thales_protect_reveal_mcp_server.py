from decimal import Decimal, InvalidOperation
from typing import Any
import string
import requests
import json
import pandas as pd
from pyspark.sql.functions import pandas_udf
from pyspark.sql.types import StringType
from mcp.server.fastmcp import FastMCP
import os
import re
import asyncio

# Determine the path to the current script's directory
current_dir = os.path.dirname(__file__)

# Construct the relative path to the properties file
properties_file_path = os.path.join(current_dir, 'udfConfigmcp-cloud.properties')


# Load properties from the configuration file
properties = {}
try:
    with open(properties_file_path, 'r') as prop_file:
        # Example logic to parse the properties file
        for line in prop_file:
            if '=' in line:
                key, value = line.strip().split('=', 1)
                properties[key] = value
except FileNotFoundError:
    print(f"Properties file not found at {properties_file_path}")

BADDATATAG = "9999999999999999"
REVEALRETURNTAG = "data"
PROTECTRETURNTAG = "protected_data"

mcp = FastMCP("Thales CRDP MCP Server ")


@mcp.tool()
async def thales_udf(inputdata: str, mode: str, datatype: str)-> Any:
    """
    Encrypt sensitive data using Thales protect and reveal REST API

    Args:
        inputdata (str): The sensitive data to protect
        mode (str): The mode protect or reveal 
        datatype (str): Either char or nbr 

    Returns:
        Any: The encrypted data
    """
    
    encdata = ""

    datatype = determine_datatype(inputdata)

    validate_results = validate_input(inputdata)
    if validate_results.startswith("invalid"):
        return inputdata

       # Fetch properties
    crdpip = properties.get("CRDPIP")
    if crdpip is None:
        print(f"'{"CRDPIP"}' not found in properties file, checking environment variables...")
        crdpip = os.environ.get("CRDPIP")
    if crdpip is not None:
        print(f"CRDPIP resolved to: {crdpip}")
    else:
        print(f"Warning: '{"CRDPIP"}' not found in properties file or environment variables. Using a default or raising an error.")


    user_name = properties.get("user_name")
    if user_name is None:
        print(f"'{"user_name"}' not found in properties file, checking environment variables...")
        user_name = os.environ.get("user_name")
    if user_name is not None:
        print(f"user_name resolved to: {user_name}")
    else:
        print(f"Warning: '{"user_name"}' not found in properties file or environment variables. Using a default or raising an error.")


    return_ciphertext_for_user_without_key_access = (
        properties.get("returnciphertextforuserwithnokeyaccess", "no").lower() == "yes"
    )
 
    key_metadata_location = properties.get("keymetadatalocation")
    external_version_from_ext_source = properties.get("keymetadata")
    if datatype == "char":
        protection_profile = properties.get("protection_profile_char")
    else:
        protection_profile = properties.get("protection_profile_nbr")

    #Print protection profile and key metadata location for debugging
    #print("Protection Profile:", protection_profile)
    #print("Key Metadata Location:", key_metadata_location)

    data_key = "data"
    if mode == "reveal":
        data_key = "protected_data"

    try:
        json_tag_for_protect_reveal = (
            PROTECTRETURNTAG if mode == "protect" else REVEALRETURNTAG
        )
        show_reveal_key = (
            properties.get("showrevealinternalkey", "yes").lower() == "yes"
        )

        sensitive = inputdata

        # Prepare payload for the protect/reveal request
        crdp_payload = {
            "protection_policy_name": protection_profile,
            data_key: sensitive,
        }

        if mode == "reveal":
            crdp_payload["username"] = user_name
            if key_metadata_location.lower() == "external":
                crdp_payload["external_version"] = external_version_from_ext_source

        # Construct URL and make the HTTP request
        url_str = f"http://{crdpip}:8090/v1/{mode}"
        headers = {"Content-Type": "application/json"}

        response = requests.post(
            url_str, headers=headers, data=json.dumps(crdp_payload)
        )
        response_json = response.json()

        if response.ok:
            protected_data = response_json.get(json_tag_for_protect_reveal)
            if (
                mode == "protect"
                and key_metadata_location.lower() == "internal"
                and not show_reveal_key
            ):
                protected_data = (
                    protected_data[7:] if len(protected_data) > 7 else protected_data
                )
            encdata = protected_data
        else:
            raise ValueError(f"Request failed with status code: {response.status_code}")
    except Exception as e:
        print(f"Exception occurred: {e}")
        if return_ciphertext_for_user_without_key_access:
            pass
        else:
            raise e

    return encdata

def determine_datatype(input_data):
    # Pattern for numbers with common separators
    numeric_pattern = r'^[\d\-\s\(\)\.]+$'
    
    if re.match(numeric_pattern, input_data):
        # Further check if it contains actual digits
        if any(c.isdigit() for c in input_data):
            return "nbr"
    
    return "char"

def validate_input(value):
    # Define special characters
    special_characters = set(string.punctuation)
    
    # Check if the input is less than 2 characters
    if len(value) < 2:
        return "invalid"
    
    # Check if the length is 2 and one of the characters is a special character
    if len(value) == 2 and any(char in special_characters for char in value):
        return "invalid"
    
    return "valid"


if __name__ == "__main__":
    print("Starting Thales CRDP MCP")
    mcp.run(transport="sse")
