#!/usr/bin/python

# AWS profile you are referencing for authentication.  If you don't have a profile set to "default"
# aws_profile = "default"
aws_profile = "firstwatch"

# AWS region you want to run in.
aws_region = "us-east-1"  # for local testing
# aws_region = "us-west-2"

# Comma delimited array of quoted instance names to encrypt the volumes for.
instance_names = ["UpdateMe"]

# AWS encryption key ARN to use if you're not using the default AWS key.  Full ARN.
# If you want to use the default AWS\ebs key, just leave blank
# aws_encryption_key_arn = ""
aws_encryption_key_arn = "arn:aws:kms:us-east-1:955241386426:key/788db8b3-1e19-4af2-bf43-2cbe3cfbc985"

# NEW OPTIONS
# encrypt_all: set to true if you want to encrypt all volumes instead of just root.
# encrypt_all = False
encrypt_all = False

# ignore_encrypted: 
# -- Set to true to ignore volumes that are already encrypted.  
# -- Set to false to re-encrypt volumes if the configuration key doesn't match the current encryption key.
# ignore_encrypted = True
ignore_encrypted = False

# generate_report: will generate some information helpful for updating terraform state files or other documentation
generate_report = True

# force_volume_types: will force all created volumes to a particular type (e.g. gp2)
force_volume_type = "gp2"
