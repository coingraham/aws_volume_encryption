#! /usr/bin/python

"""
Overview:
    Encrypt the root or ALL volumes by system instance_name.  Can do up to five systems at a time.
Params:
    All parameters are handled by the configuration file (aws_volume_encryption_config.py)
Conditions:
    Will return a log of activities and their results
"""

import boto3
import botocore
import aws_volume_encryption_config
from multiprocessing import Pool


class InstanceVolumeEncryptor:
    def __init__(self, instance_name):

        """ Set up AWS Session + Client + Resources + Waiters """
        self.instance_name = instance_name
        self.aws_profile = aws_volume_encryption_config.aws_profile
        self.aws_region = aws_volume_encryption_config.aws_region
        self.encrypt_all = aws_volume_encryption_config.encrypt_all
        self.ignore_encrypted = aws_volume_encryption_config.ignore_encrypted
        self.generate_report = aws_volume_encryption_config.generate_report
        self.force_volume_type = aws_volume_encryption_config.force_volume_type
        self.instance = None
        self.volume_queue = []
        self.instance_id = ""
        self.instance_volume_mappings = []

        # Create custom session
        self.session = boto3.session.Session(profile_name=self.aws_profile, region_name=self.aws_region)

        # Get CMK
        self.aws_encryption_key_arn = aws_volume_encryption_config.aws_encryption_key_arn

        # Pre-create the clients for reuse
        self.ec2_client = self.session.client("ec2")
        self.ec2_resource = self.session.resource("ec2")

        # Pre-create and configure the waiters
        self.waiter_instance_exists = self.ec2_client.get_waiter("instance_exists")
        self.waiter_instance_stopped = self.ec2_client.get_waiter("instance_stopped")
        self.waiter_instance_running = self.ec2_client.get_waiter("instance_running")
        self.waiter_snapshot_complete = self.ec2_client.get_waiter("snapshot_completed")
        self.waiter_volume_available = self.ec2_client.get_waiter("volume_available")
        self.waiter_volume_in_use = self.ec2_client.get_waiter("volume_in_use")

    def encrypt_instance_volumes(self):

        self.get_instance_info_from_name()

        # Save instance volume mappings and tags to persist to new volume
        for block_device_mapping in self.instance.block_device_mappings:
            device_id = block_device_mapping["Ebs"]["VolumeId"]
            device_name = block_device_mapping["DeviceName"]
            delete_on_termination = block_device_mapping["Ebs"]["DeleteOnTermination"]
            volume = self.ec2_resource.Volume(device_id)
            self.instance_volume_mappings.append({
                "VolumeId": device_id,
                "Volume": volume,
                "DeleteOnTermination": delete_on_termination,
                "DeviceName": device_name,
            })

        for v in self.instance_volume_mappings:
            if v["DeviceName"] == self.instance.root_device_name:
                if v["Volume"].encrypted:
                    # If the volume is already encrypted, decide what do to.
                    if self.ignore_encrypted is False and v["Volume"].kms_key_id != self.aws_encryption_key_arn:
                        self.volume_queue.append(v)

                else:
                    # If not encrypted, add to queue
                    self.volume_queue.append(v)

            elif self.encrypt_all:
                # Inspect non-root volumes to add to the queue
                if v["Volume"].encrypted:
                    # If the volume is already encrypted, decide what do to.
                    if self.ignore_encrypted is False and v["Volume"].kms_key_id != self.aws_encryption_key_arn:
                        self.volume_queue.append(v)

                else:
                    # If not encrypted, add to queue
                    self.volume_queue.append(v)

        if len(self.volume_queue) > 0:
            self.stop_instance()
            for volume in self.volume_queue:
                self.process_volume(volume["Volume"], volume["DeviceName"], volume["DeleteOnTermination"])

            self.start_instance()

            if self.generate_report:
                # Print a report of the new mappings
                print("\n---New volume mappings for {}".format(self.instance_name))
                for block_device_mapping in self.instance.block_device_mappings:
                    device_id = block_device_mapping["Ebs"]["VolumeId"]
                    device_name = block_device_mapping["DeviceName"]
                    print("---Volume {} is attached at {}".format(device_id, device_name))

        else:
            print("---No volumes to encrypt for {}".format(self.instance_name))

        print("\n****Encryption finished for {}".format(self.instance_name))

    def process_volume(self, volume, device_name, delete_on_termination):
        print("\n---Processing volume ({}) attached to {} on {}".format(volume.id, device_name, self.instance_name))
        print("---Create snapshot of volume ({}) for {}".format(volume.id, self.instance_name))

        snapshot = self.ec2_resource.create_snapshot(
            VolumeId=volume.id,
            Description="Snapshot of volume ({}) for {}".format(volume.id, self.instance_name),
        )

        # Set the max_attempts for this waiter (default 40)
        self.waiter_snapshot_complete.config.max_attempts = 120

        try:
            self.waiter_snapshot_complete.wait(
                SnapshotIds=[
                    snapshot.id,
                ]
            )
        except botocore.exceptions.WaiterError as e:
            snapshot.delete()
            return "ERROR: {} on {}".format(e, self.instance_name)

        """ Step 3: Create encrypted volume """
        print("---Create encrypted copy of snapshot for ({})".format(volume.id))

        if self.aws_encryption_key_arn:
            # Use custom key
            snapshot_encrypted_dict = snapshot.copy(
                SourceRegion=self.session.region_name,
                Description="Encrypted copy of snapshot ({}) for {}"
                            .format(snapshot.id, self.instance_name),
                KmsKeyId=self.aws_encryption_key_arn,
                Encrypted=True,
            )
        else:
            # Use default key
            snapshot_encrypted_dict = snapshot.copy(
                SourceRegion=self.session.region_name,
                Description="Encrypted copy of snapshot ({}) for {}"
                            .format(snapshot.id, self.instance_name),
                Encrypted=True,
            )

        snapshot_encrypted = self.ec2_resource.Snapshot(snapshot_encrypted_dict["SnapshotId"])

        # Set the max_attempts for this waiter (default 40)
        self.waiter_snapshot_complete.config.max_attempts = 120

        try:
            self.waiter_snapshot_complete.wait(
                SnapshotIds=[
                    snapshot_encrypted.id,
                ],
            )
        except botocore.exceptions.WaiterError as e:
            snapshot.delete()
            snapshot_encrypted.delete()
            return "ERROR: {} on {}".format(e, self.instance_name)

        print("---Create encrypted volume from snapshot for ({})".format(volume.id))

        if self.force_volume_type is not volume.volume_type:
            update_volume_type = self.force_volume_type
        else:
            update_volume_type = volume.volume_type

        volume_encrypted = self.ec2_resource.create_volume(
            SnapshotId=snapshot_encrypted.id,
            AvailabilityZone=self.instance.placement["AvailabilityZone"],
            VolumeType=update_volume_type,
        )

        # Wait for the volume to be available before updating the tags.
        try:
            self.waiter_volume_available.wait(
                VolumeIds=[
                    volume_encrypted.id,
                ],
            )
        except botocore.exceptions.WaiterError as e:
            snapshot.delete()
            snapshot_encrypted.delete()
            volume_encrypted.delete()
            return "ERROR: {} on {}".format(e, self.instance_name)

        volume_encrypted.create_tags(Tags=volume.tags)

        print("---Detach volume ({}) for {}".format(volume.id, self.instance_name))
        self.instance.detach_volume(
            VolumeId=volume.id,
            Device=device_name,
        )

        # Wait for the old volume to be detached before attaching the new volume.
        try:
            self.waiter_volume_available.wait(
                VolumeIds=[
                    volume.id,
                ],
            )
        except botocore.exceptions.WaiterError as e:
            snapshot.delete()
            snapshot_encrypted.delete()
            volume_encrypted.delete()
            return "ERROR: {} on {}".format(e, self.instance_name)

        print("---Attach volume ({}) for {}".format(volume_encrypted.id, self.instance_name))

        self.instance.attach_volume(
            VolumeId=volume_encrypted.id,
            Device=device_name
        )

        # Modify instance attributes
        self.instance.modify_attribute(
            BlockDeviceMappings=[
                {
                    "DeviceName": device_name,
                    "Ebs": {
                        "DeleteOnTermination": delete_on_termination,
                    },
                },
            ],
        )

        print("---Clean up resources for ({})".format(volume.id))
        # Delete snapshots and original volume
        snapshot.delete()
        snapshot_encrypted.delete()
        volume.delete()

        print("---Encryption finished for ({})".format(volume.id))

    def stop_instance(self):
        # Exit if instance is pending, shutting-down, or terminated
        instance_exit_states = [0, 32, 48]
        if self.instance.state["Code"] in instance_exit_states:
            raise "ERROR: Instance is {} please make sure this instance ({}) is active.".format(
                self.instance.state["Name"],
                self.instance_name
            )

        # Validate successful shutdown if it is running or stopping
        if self.instance.state["Code"] is 16:
            self.instance.stop()

        # Set the max_attempts for this waiter (default 40)
        self.waiter_instance_stopped.config.max_attempts = 40

        try:
            self.waiter_instance_stopped.wait(
                InstanceIds=[
                    self.instance.id,
                ]
            )
        except botocore.exceptions.WaiterError as e:
            raise "ERROR: {} on {}".format(e, self.instance_name)

    def start_instance(self):
        print("---Restart instance {}".format(self.instance_name))
        self.instance.start()

        try:
            self.waiter_instance_running.wait(
                InstanceIds=[
                    self.instance_id,
                ]
            )
        except botocore.exceptions.WaiterError as e:
            raise "ERROR: {} on {}".format(e, self.instance_name)

    def get_instance_info_from_name(self):

        name_filter = [{
            "Name": "tag:Name",
            "Values": [self.instance_name]
        }]

        try:
            reservations = self.ec2_client.describe_instances(Filters=name_filter)

            if len(reservations[u"Reservations"]) == 1 and len(reservations[u"Reservations"][0][u"Instances"]) == 1:

                for _instance in reservations[u"Reservations"][0][u"Instances"]:
                    tags = dict([(t["Key"], t["Value"]) for t in _instance["Tags"]])

                    if self.instance_name in tags.values():
                        self.instance_id = _instance[u"InstanceId"]

            else:
                raise "ERROR: Ambiguous instance_name {}".format(self.instance_name)

        except:
            raise "ERROR: Check instance_name {}".format(self.instance_name)

        print("****Checking instance ({}) called {}".format(self.instance_id, self.instance_name))
        self.instance = self.ec2_resource.Instance(self.instance_id)

        try:
            self.waiter_instance_exists.wait(
                InstanceIds=[
                    self.instance_id,
                ]
            )
        except botocore.exceptions.WaiterError as e:
            return "ERROR: {} on {}".format(e, self.instance_name)


def worker(name):

    # Each worker creates a VolumeEncryption obj
    ve = InstanceVolumeEncryptor(name)
    ve.encrypt_instance_volumes()


if __name__ == "__main__":

    # Get the list of instance names from the config file.
    instance_names = aws_volume_encryption_config.instance_names

    # Make sure there are names in the list and run a process for each.
    if len(instance_names) > 0:

        # Uncomment if you want to run in parallel (you can only do 5 snaps at a time)
        if len(instance_names) > 5:
            max_pool_size = 5
        else:
            max_pool_size = len(instance_names)

        # Instantiate the tool
        p = Pool(max_pool_size)
        p.map(worker, instance_names)

    else:
        print("---Missing list of instance names in config")
