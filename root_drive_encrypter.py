#! /usr/bin/python

"""
Overview:
    Take unencrypted root volume and encrypt it for EC2.
Params:
    ID for EC2 instance
    Customer Master Key (CMK) (optional)
    Profile to use
Conditions:
    Return if volume already encrypted
    Use named profiles from credentials file
"""

import boto3
import botocore
import root_drive_encrypter_config
from multiprocessing import Pool


def encrypt_root(name):

    """ Set up AWS Session + Client + Resources + Waiters """
    profile = root_drive_encrypter_config.profile

    # Create custom session
    # print("Using profile {}".format(profile))
    session = boto3.session.Session(profile_name=profile)

    # Get CMK
    customer_master_key = root_drive_encrypter_config.customer_master_key

    client = session.client("ec2")
    ec2 = session.resource("ec2")

    waiter_instance_exists = client.get_waiter("instance_exists")
    waiter_instance_stopped = client.get_waiter("instance_stopped")
    waiter_instance_running = client.get_waiter("instance_running")
    waiter_snapshot_complete = client.get_waiter("snapshot_completed")
    waiter_volume_available = client.get_waiter("volume_available")

    """ Get Instance Id from Name Tag """
    name_filter = [{
        "Name": "tag:Name",
        "Values": [name]
    }]

    try:
        reservations = client.describe_instances(Filters=name_filter)

        if len(reservations[u"Reservations"]) == 1 and len(reservations[u"Reservations"][0][u"Instances"]) == 1:

            for instance in reservations[u"Reservations"][0][u"Instances"]:
                tags = dict([(t["Key"], t["Value"]) for t in instance["Tags"]])

                if name in tags.values():
                    instance_id = instance[u"InstanceId"]

        else:
            return "ERROR: Ambiguous name {}".format(name)

    except:
        return "ERROR: Check name {}".format(name)

    """ Check instance exists """
    print("---Checking instance ({}) called {}".format(instance_id, name))
    instance = ec2.Instance(instance_id)

    try:
        waiter_instance_exists.wait(
            InstanceIds=[
                instance_id,
            ]
        )
    except botocore.exceptions.WaiterError as e:
        return "ERROR: {} on {}".format(e, name)

    """ Get volume and exit if already encrypted """
    volumes = [v for v in instance.volumes.all()]
    if volumes:
        original_root_volume = volumes[0]
        volume_encrypted = original_root_volume.encrypted
        if volume_encrypted:
            print("**Volume ({}) is already encrypted on {}**".format(original_root_volume.id, name))
            return "**Volume ({}) is already encrypted on {}**".format(original_root_volume.id, name)

    """ Step 1: Prepare instance """
    print("---Preparing instance {}".format(name))
    # Save original mappings to persist to new volume
    original_mappings = {"DeleteOnTermination": instance.block_device_mappings[0]["Ebs"]["DeleteOnTermination"]}

    # Exit if instance is pending, shutting-down, or terminated
    instance_exit_states = [0, 32, 48]
    if instance.state["Code"] in instance_exit_states:
        return "ERROR: Instance is {} please make sure this instance ({}) is active.".format(
            instance.state["Name"],
            name
        )

    # Validate successful shutdown if it is running or stopping
    if instance.state["Code"] is 16:
        instance.stop()

    # Set the max_attempts for this waiter (default 40)
    waiter_instance_stopped.config.max_attempts = 40

    try:
        waiter_instance_stopped.wait(
            InstanceIds=[
                instance_id,
            ]
        )
    except botocore.exceptions.WaiterError as e:
        return "ERROR: {} on {}".format(e, name)

    """ Step 2: Take snapshot of volume """
    print("---Create snapshot of volume ({}) for {}".format(original_root_volume.id, name))

    snapshot = ec2.create_snapshot(
        VolumeId=original_root_volume.id,
        Description="Snapshot of volume ({}) for {}".format(original_root_volume.id, name),
    )

    try:
        waiter_snapshot_complete.wait(
            SnapshotIds=[
                snapshot.id,
            ]
        )
    except botocore.exceptions.WaiterError as e:
        snapshot.delete()
        return "ERROR: {} on {}".format(e, name)

    """ Step 3: Create encrypted volume """
    print("---Create encrypted copy of snapshot for {}".format(name))

    if customer_master_key:
        # Use custom key
        snapshot_encrypted_dict = snapshot.copy(
            SourceRegion=session.region_name,
            Description="Encrypted copy of snapshot ({}) for {}"
                        .format(snapshot.id, name),
            KmsKeyId=customer_master_key,
            Encrypted=True,
        )
    else:
        # Use default key
        snapshot_encrypted_dict = snapshot.copy(
            SourceRegion=session.region_name,
            Description="Encrypted copy of snapshot ({}) for {}"
                        .format(snapshot.id, name),
            Encrypted=True,
        )

    snapshot_encrypted = ec2.Snapshot(snapshot_encrypted_dict["SnapshotId"])

    try:
        waiter_snapshot_complete.wait(
            SnapshotIds=[
                snapshot_encrypted.id,
            ],
        )
    except botocore.exceptions.WaiterError as e:
        snapshot.delete()
        snapshot_encrypted.delete()
        return "ERROR: {} on {}".format(e, name)

    print("---Create encrypted volume from snapshot for {}".format(name))
    volume_encrypted = ec2.create_volume(
        SnapshotId=snapshot_encrypted.id,
        AvailabilityZone=instance.placement["AvailabilityZone"]
    )

    """ Step 4: Detach current root volume """
    print("---Detach volume {} for {}".format(original_root_volume.id, name))
    instance.detach_volume(
        VolumeId=original_root_volume.id,
        Device=instance.root_device_name,
    )

    """ Step 5: Attach current root volume """
    print("---Attach volume {} for {}".format(volume_encrypted.id, name))
    try:
        waiter_volume_available.wait(
            VolumeIds=[
                volume_encrypted.id,
            ],
        )
    except botocore.exceptions.WaiterError as e:
        snapshot.delete()
        snapshot_encrypted.delete()
        volume_encrypted.delete()
        return "ERROR: {} on {}".format(e, name)

    instance.attach_volume(
        VolumeId=volume_encrypted.id,
        Device=instance.root_device_name
    )

    """ Step 6: Restart instance """
    # Modify instance attributes
    instance.modify_attribute(
        BlockDeviceMappings=[
            {
                "DeviceName": instance.root_device_name,
                "Ebs": {
                    "DeleteOnTermination":
                    original_mappings["DeleteOnTermination"],
                },
            },
        ],
    )
    print("---Restart instance {}".format(name))
    instance.start()

    try:
        waiter_instance_running.wait(
            InstanceIds=[
                instance_id,
            ]
        )
    except botocore.exceptions.WaiterError as e:
        return "ERROR: {} on {}".format(e, name)

    """ Step 7: Clean up """
    print("---Clean up resources for {}".format(name))
    # Delete snapshots and original volume
    snapshot.delete()
    snapshot_encrypted.delete()
    original_root_volume.delete()

    print("---Encryption finished for {}".format(name))
    return "Encryption finished for {}".format(name)

if __name__ == "__main__":

    # Get the list of instance names from the config file.
    names = root_drive_encrypter_config.names

    # Make sure there are names in the list and run a process for each.
    if len(names) > 0:
        p = Pool(len(names))
        print(p.map(encrypt_root, names))
    else:
        print("---Missing list of instance names in config")

