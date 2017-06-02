#!/usr/bin/python

# Profile you are referencing for authentication
# profile = "firstwatch"  # for local testing
profile = "FSOP_Admin"

# Region you want to run in.
# region = "us-east-1"  # for local testing
region = "us-west-2"

# Comma delimited array of quoted instance names to encrypt the root drive.
names = ["CLPJDEA5001","CLPJDEA5002","CLPJDEA5003","CLPJDEA5004","CLPJDED5001","CWPJDEA5001"]
# names = ["Test"]

# Customer Master Key to use if you're not using the default AWS key.  Full ARN.
customer_master_key = "arn:aws:kms:us-west-2:644198608768:key/ce34a0b0-f0fd-4fff-b455-d927e28dec60"
