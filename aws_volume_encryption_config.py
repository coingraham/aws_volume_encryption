#!/usr/bin/python

# Profile you are referencing for authentication
# profile = "firstwatch"  # for local testing
profile = "firstwatch"

# Region you want to run in.
region = "us-east-1"  # for local testing
# region = "us-west-2"

# Comma delimited array of quoted instance names to encrypt the root drive.
names = ["encryptme1","encryptme2","encryptme3"]
# names = ["Test"]

# Customer Master Key to use if you're not using the default AWS key.  Full ARN.
customer_master_key = "arn:aws:kms:us-east-1:955241386426:key/0dcfa321-57eb-4d02-b275-5cc6d7c8f396"