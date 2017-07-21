#!/usr/bin/python

# Profile you are referencing for authentication
# profile = "myprofile"  # for local testing
profile = "firstwatch"

# Region you want to run in.
region = "us-east-1"  # for local testing
# region = "us-west-2"

# Comma delimited array of quoted instance names to encrypt the root drive.
names = ["Remediate"]

# Customer Master Key to use if you're not using the default AWS key.  Full ARN.
customer_master_key = "arn:aws:kms:us-east-1:955241386426:key/788db8b3-1e19-4af2-bf43-2cbe3cfbc985"

# NEW OPTIONS
# encrypt_all: set to true if you want to encrypt all volumes instead of just root
encrypt_all = True

# ignore_encrypted: 
# -- Set to true to ignore volumes that are already encrypted.  
# -- Set to false to re-encrypt volumes if the configuration key doesn't match the actual key
ignore_encrypted = False

# generate_report: will generate some information helpful for updating terraform state files for example
generate_report = True
