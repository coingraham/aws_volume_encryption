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
import aws_volume_encryption_config
from multiprocessing import Pool


class VolumeEncryption:
    def __init__(self, _name):

        """ Set up AWS Session + Client + Resources + Waiters """
        self.name = _name
        self.profile = aws_volume_encryption_config.profile
        self.region = aws_volume_encryption_config.region
        self.encrypt_all = aws_volume_encryption_config.encrypt_all
        self.ignore_encrypted = aws_volume_encryption_config.ignore_encrypted
        self.generate_report = aws_volume_encryption_config.generate_report
        self.instance = None
        self.volume_queue = []
        self.instance_id = ""
        self.original_mappings = []

        # Create custom session
        self.session = boto3.session.Session(profile_name=self.profile, region_name=self.region)

        # Get CMK
        self.customer_master_key = aws_volume_encryption_config.customer_master_key

        # Pre-create the clients for reuse
        self.ec2_client = self.session.client("ec2")
        self.ec2_resource = self.session.resource("ec2")

        # Pre-create and configure the waiters
        self.waiter_instance_exists = self.ec2_client.get_waiter("instance_exists")
        self.waiter_instance_stopped = self.ec2_client.get_waiter("instance_stopped")
        self.waiter_instance_running = self.ec2_client.get_waiter("instance_running")
        self.waiter_snapshot_complete = self.ec2_client.get_waiter("snapshot_completed")
        self.waiter_volume_available = self.ec2_client.get_waiter("volume_available")

    def encrypt_volumes(self):

        self.get_instance_id_from_name()

        # Save original mappings to persist to new volume
        for block_device_mapping in self.instance.block_device_mappings:
            device_id = block_device_mapping["Ebs"]["VolumeId"]
            device_name = block_device_mapping["DeviceName"]
            delete_on_termination = block_device_mapping["Ebs"]["DeleteOnTermination"]
            volume = self.ec2_resource.Volume(device_id)
            self.original_mappings.append({
                "VolumeId": device_id,
                "Volume": volume,
                "DeleteOnTermination": delete_on_termination,
                "DeviceName": device_name,
            })

        for v in self.original_mappings:
            if v["DeviceName"] == self.instance.root_device_name:
                if v["Volume"].encrypted:
                    # If the volume is already encrypted, decide what do to.
                    if self.ignore_encrypted is False and v["Volume"].kms_key_id != self.customer_master_key:
                        self.volume_queue.append(v)

                else:
                    # If not encrypted, add to queue
                    self.volume_queue.append(v)

            elif self.encrypt_all:
                # Inspect non-root volumes to add to the queue
                if v["Volume"].encrypted:
                    # If the volume is already encrypted, decide what do to.
                    if self.ignore_encrypted is False and v["Volume"].kms_key_id != self.customer_master_key:
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
                print("\n---New volume mappings for {}".format(self.name))
                for block_device_mapping in self.instance.block_device_mappings:
                    device_id = block_device_mapping["Ebs"]["VolumeId"]
                    device_name = block_device_mapping["DeviceName"]
                    print("---Volume {} is attached at {}".format(device_id, device_name))

        else:
            print("---No volumes to encrypt for {}".format(self.name))

        print("\n****Encryption finished for {}".format(self.name))

    def process_volume(self, volume, device_name, delete_on_termination):
        print("\n---Processing volume ({}) attached to {} on {}".format(volume.id, device_name, self.name))
        print("---Create snapshot of volume ({}) for {}".format(volume.id, self.name))

        snapshot = self.ec2_resource.create_snapshot(
            VolumeId=volume.id,
            Description="Snapshot of volume ({}) for {}".format(volume.id, self.name),
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
            return "ERROR: {} on {}".format(e, self.name)

        """ Step 3: Create encrypted volume """
        print("---Create encrypted copy of snapshot for ({})".format(volume.id))

        if self.customer_master_key:
            # Use custom key
            snapshot_encrypted_dict = snapshot.copy(
                SourceRegion=self.session.region_name,
                Description="Encrypted copy of snapshot ({}) for {}"
                            .format(snapshot.id, self.name),
                KmsKeyId=self.customer_master_key,
                Encrypted=True,
            )
        else:
            # Use default key
            snapshot_encrypted_dict = snapshot.copy(
                SourceRegion=self.session.region_name,
                Description="Encrypted copy of snapshot ({}) for {}"
                            .format(snapshot.id, self.name),
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
            return "ERROR: {} on {}".format(e, self.name)

        print("---Create encrypted volume from snapshot for ({})".format(volume.id))
        volume_encrypted = self.ec2_resource.create_volume(
            SnapshotId=snapshot_encrypted.id,
            AvailabilityZone=self.instance.placement["AvailabilityZone"]
        )

        print("---Detach volume ({}) for {}".format(volume.id, self.name))
        self.instance.detach_volume(
            VolumeId=volume.id,
            Device=device_name,
        )

        print("---Attach volume ({}) for {}".format(volume_encrypted.id, self.name))
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
            return "ERROR: {} on {}".format(e, self.name)

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
                self.name
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
            raise "ERROR: {} on {}".format(e, self.name)

    def start_instance(self):
        print("---Restart instance {}".format(self.name))
        self.instance.start()

        try:
            self.waiter_instance_running.wait(
                InstanceIds=[
                    self.instance_id,
                ]
            )
        except botocore.exceptions.WaiterError as e:
            raise "ERROR: {} on {}".format(e, self.name)

    def get_instance_id_from_name(self):

        name_filter = [{
            "Name": "tag:Name",
            "Values": [self.name]
        }]

        try:
            reservations = self.ec2_client.describe_instances(Filters=name_filter)

            if len(reservations[u"Reservations"]) == 1 and len(reservations[u"Reservations"][0][u"Instances"]) == 1:

                for _instance in reservations[u"Reservations"][0][u"Instances"]:
                    tags = dict([(t["Key"], t["Value"]) for t in _instance["Tags"]])

                    if self.name in tags.values():
                        self.instance_id = _instance[u"InstanceId"]

            else:
                raise "ERROR: Ambiguous name {}".format(self.name)

        except:
            raise "ERROR: Check name {}".format(self.name)

        print("****Checking instance ({}) called {}".format(self.instance_id, self.name))
        self.instance = self.ec2_resource.Instance(self.instance_id)

        try:
            self.waiter_instance_exists.wait(
                InstanceIds=[
                    self.instance_id,
                ]
            )
        except botocore.exceptions.WaiterError as e:
            return "ERROR: {} on {}".format(e, self.name)


def worker(name):

    # Each worker creates a VolumeEncryption obj
    ve = VolumeEncryption(name)
    ve.encrypt_volumes()


if __name__ == "__main__":

    # Get the list of instance names from the config file.
    names = aws_volume_encryption_config.names

    # Make sure there are names in the list and run a process for each.
    if len(names) > 0:

        # Uncomment if you want to run in parallel (you can only do 5 snaps at a time)
        if len(names) > 5:
            max_pool_size = 5
        else:
            max_pool_size = len(names)

        # Instantiate the tool
        p = Pool(max_pool_size)
        p.map(worker, names)

    else:
        print("---Missing list of instance names in config")
