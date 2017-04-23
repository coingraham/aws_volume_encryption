#!/usr/bin/python

# Profile you are referencing for authentication
# profile = "firstwatch"  # for local testing
profile = "firstwatch"

# Region you want to run in.
region = "us-east-1"  # for local testing
# region = "us-west-2"

# Comma delimited array of quoted instance names to encrypt the root drive.
names = ["CWDJDEA5001","CWDJDEA5011","CWDJDEA5012","CWDJDEA5013","CWDJDEA5014","CWDJDEA5015"]

# Customer Master Key to use if you're not using the default AWS key
customer_master_key = ""