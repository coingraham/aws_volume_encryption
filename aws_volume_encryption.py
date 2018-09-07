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
import botocore.exceptions as exceptions
import argparse
import aws_volume_encryption_config
from multiprocessing import Pool


class InstanceVolumeEncryptor:
    def __init__(self, _profile,
                 _region="us-east-1",
                 _generate_report=True,
                 _instance_name=None,
                 _instance_id=None,
                 _encrypt_all=False,
                 _ignore_encrypted=True,
                 _force_volume_type="gp2",
                 _encryption_key_arn=None,
                 _keep_snapshots=False
                 ):

        # Set up AWS Session + Client + Resources + Waiters
        self.aws_profile = _profile
        self.aws_region = _region
        self.encrypt_all = _encrypt_all
        self.ignore_encrypted = _ignore_encrypted
        self.generate_report = _generate_report
        self.force_volume_type = _force_volume_type
        self.keep_snapshots = _keep_snapshots
        self.instance = None
        self.volume_queue = []

        if _instance_name is not None:
            self.instance_name = _instance_name
            self.instance_identification = _instance_name
        else:
            self.instance_name = ""

        if _instance_id is not None:
            self.instance_id = _instance_id
            self.instance_identification = _instance_id
        else:
            self.instance_id = ""

        self.instance_volume_mappings = []

        # Create custom session
        self.session = boto3.session.Session(profile_name=self.aws_profile, region_name=self.aws_region)

        # Get CMK
        if _encryption_key_arn is not None:
            self.aws_encryption_key_arn = _encryption_key_arn
        else:
            self.aws_encryption_key_arn = ""

        # Pre-create the clients for reuse
        self.ec2_client = self.session.client("ec2")
        self.ec2_resource = self.session.resource("ec2")

        # Pre-create and configure the waiters
        self.waiter_instance_exists = self.ec2_client.get_waiter("instance_exists")
        self.waiter_instance_exists.config.max_attempts = 2
        self.waiter_instance_stopped = self.ec2_client.get_waiter("instance_stopped")
        self.waiter_instance_running = self.ec2_client.get_waiter("instance_running")
        self.waiter_snapshot_complete = self.ec2_client.get_waiter("snapshot_completed")
        self.waiter_volume_available = self.ec2_client.get_waiter("volume_available")
        self.waiter_volume_in_use = self.ec2_client.get_waiter("volume_in_use")

    def encrypt_instance_volumes(self):

        if self.instance_id == "":
            # Get the instance information from the name tag
            self.get_instance_info_from_name()
        else:

            print("****Checking instance {}.".format(self.instance_identification))
            self.instance = self.ec2_resource.Instance(self.instance_id)

            try:
                self.waiter_instance_exists.wait(
                    InstanceIds=[
                        self.instance_id,
                    ]
                )
            except botocore.exceptions.WaiterError as e:
                if "Max attempts exceeded" in e.message:
                    return "****Instance {} not found in {}.".format(self.instance_identification, self.aws_region)
                else:
                    return "ERROR: {} on {}".format(e, self.instance_identification)

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

        # Iterate through the volumes and decide what to do.
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

            # If there are any volumes to action against, stop the instance.
            self.stop_instance()

            for volume in self.volume_queue:
                self.process_volume(volume["Volume"], volume["DeviceName"], volume["DeleteOnTermination"])

            # Once all the volumes are done being manipulated, start the system back.
            self.start_instance()

            # Print out the new volume information
            if self.generate_report:
                # Print a report of the new mappings
                print("\n---New volume mappings for {}".format(self.instance_identification))
                for block_device_mapping in self.instance.block_device_mappings:
                    device_id = block_device_mapping["Ebs"]["VolumeId"]
                    device_name = block_device_mapping["DeviceName"]
                    print("---Volume {} is attached at {}".format(device_id, device_name))

        else:
            print("---No volumes to encrypt for {}".format(self.instance_identification))

        print("\n****Encryption finished for {}".format(self.instance_identification))

    def process_volume(self, volume, device_name, delete_on_termination):

        print("\n---Processing volume {} attached to {} on {}".format(volume.id, device_name,
                                                                        self.instance_identification))

        # Take a snapshot and wait until it's complete.
        print("---Create snapshot of volume {} for {}".format(volume.id, self.instance_identification))

        snapshot = self.ec2_resource.create_snapshot(
            VolumeId=volume.id,
            Description="Snapshot of volume {} for {}".format(volume.id, self.instance_identification),
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
            return "ERROR: {} on {}".format(e, self.instance_identification)

        # Copy the snapshot and encrypt it.
        print("---Create encrypted copy of snapshot for {}".format(volume.id))

        if self.aws_encryption_key_arn:
            # Use custom key
            snapshot_encrypted_dict = snapshot.copy(
                SourceRegion=self.session.region_name,
                Description="Encrypted copy of snapshot {} for {}"
                            .format(snapshot.id, self.instance_identification),
                KmsKeyId=self.aws_encryption_key_arn,
                Encrypted=True,
            )
        else:
            # Use default key
            snapshot_encrypted_dict = snapshot.copy(
                SourceRegion=self.session.region_name,
                Description="Encrypted copy of snapshot {} for {}"
                            .format(snapshot.id, self.instance_identification),
                Encrypted=True,
            )

        # Get the snapshot object from the copy response and wait.
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
            return "ERROR: {} on {}".format(e, self.instance_identification)

        # Create a new volume from the encrypted snapshot and wait.
        print("---Create encrypted volume from snapshot for {}".format(volume.id))

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
            return "ERROR: {} on {}".format(e, self.instance_identification)

        # Update the tags to match the old tags if they exist
        if volume.tags:
            volume_encrypted.create_tags(Tags=volume.tags)

        # Switch the original volume for the new volume.
        print("---Detach volume {} for {}".format(volume.id, self.instance_identification))
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
            return "ERROR: {} on {}".format(e, self.instance_identification)

        print("---Attach volume {} for {}".format(volume_encrypted.id, self.instance_identification))

        self.instance.attach_volume(
            VolumeId=volume_encrypted.id,
            Device=device_name
        )

        # Modify instance volume attributes to match the original.
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

        # Delete snapshots and original volume
        # TODO: Need to move this to a separate function that gets called on exception

        print("---Clean up resources for {}".format(volume.id))

        if self.keep_snapshots:
            print("---Keeping snapshot {} per the configuration.".format(snapshot.id))
            snapshot_encrypted.delete()
            volume.delete()
        else:
            snapshot.delete()
            snapshot_encrypted.delete()
            volume.delete()

        print("---Encryption finished for {}".format(volume.id))

    def stop_instance(self):

        print("****Stopping instance {}".format(self.instance_identification))

        # Exit if instance is pending, shutting-down, or terminated
        instance_exit_states = [0, 32, 48]
        if self.instance.state["Code"] in instance_exit_states:
            raise Exception("ERROR: Instance is {} please make sure this instance {} is active.".format(
                self.instance.state["Name"],
                self.instance_name
            ))

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
            raise Exception("ERROR: {} on {}".format(e, self.instance_identification))

    def start_instance(self):

        # Start the instance and wait until it's running
        print("---Restart instance {}".format(self.instance_identification))
        self.instance.start()

        try:
            self.waiter_instance_running.wait(
                InstanceIds=[
                    self.instance_id,
                ]
            )
        except botocore.exceptions.WaiterError as e:
            raise Exception("ERROR: {} on {}".format(e, self.instance_identification))

    def get_instance_info_from_name(self):

        # Setup the filter for getting the instance
        name_filter = [{
            "Name": "tag:Name",
            "Values": [self.instance_name]
        }]

        # Get the reservations for the name tag and get the instance id from the reservations
        try:
            reservations = self.ec2_client.describe_instances(Filters=name_filter)

            if len(reservations[u"Reservations"]) == 1 and len(reservations[u"Reservations"][0][u"Instances"]) == 1:

                for _instance in reservations[u"Reservations"][0][u"Instances"]:
                    tags = dict([(t["Key"], t["Value"]) for t in _instance["Tags"]])

                    if self.instance_name in tags.values():
                        self.instance_id = _instance[u"InstanceId"]

            else:
                raise Exception("ERROR: Ambiguous instance_name {}".format(self.instance_identification))

        except Exception as e:
            raise Exception("ERROR: Check instance_name {}.\nReceived error {}.".format(
                self.instance_identification, e))

        # Get the instance object from the instance id and wait.
        print("****Checking instance {} called {}".format(self.instance_id, self.instance_identification))
        self.instance = self.ec2_resource.Instance(self.instance_id)

        try:
            self.waiter_instance_exists.wait(
                InstanceIds=[
                    self.instance_id,
                ]
            )
        except botocore.exceptions.WaiterError as e:
            return "ERROR: {} on {}".format(e, self.instance_identification)


class Worker:

    def __init__(self,
                 _profile,
                 _region,
                 _encrypt_all,
                 _ignore_encrypted,
                 _generate_report,
                 _force_volume_type,
                 _encryption_key_arn,
                 _instance_unknown):

        if "i-" in _instance_unknown:
            self.instance_id = _instance_unknown
            self.instance_name = None
        else:
            self.instance_name = _instance_unknown
            self.instance_id = None

        self.profile = _profile
        self.region = _region
        self.encrypt_all = _encrypt_all
        self.ignore_encrypted = _ignore_encrypted
        self.generate_report = _generate_report
        self.force_volume_type = _force_volume_type
        self.encryption_key_arn = _encryption_key_arn


def run(worker):

    # Each worker creates a VolumeEncryption obj and runs the utility.
    worker_ve = InstanceVolumeEncryptor(_profile=worker.profile,
                                        _region=worker.region,
                                        _encrypt_all=worker.encrypt_all,
                                        _ignore_encrypted=worker.ignore_encrypted,
                                        _generate_report=worker.generate_report,
                                        _force_volume_type=worker.force_volume_type,
                                        _instance_id=worker.instance_id,
                                        _instance_name=worker.instance_name)
    worker_ve.encrypt_instance_volumes()


if __name__ == "__main__":

    parser = argparse.ArgumentParser(description='aws_volume_encryption')
    parser.add_argument('--profile',
                        default=aws_volume_encryption_config.aws_profile,
                        help="The aws profile you want to use.")

    parser.add_argument('--region',
                        default=aws_volume_encryption_config.aws_region,
                        help="The aws region you want to work in.")

    parser.add_argument('--encrypt_all', choices=[True, False],
                        default=aws_volume_encryption_config.encrypt_all,
                        help="True to encrypt all the disks on the instance.  False will encrypt just the root disk.")

    parser.add_argument('--ignore_encrypted', choices=[True, False],
                        default=aws_volume_encryption_config.ignore_encrypted,
                        help="True will ignore disks that are already encrypted.  False will re-encrypt them.")

    parser.add_argument('--keep_snapshots', choices=[True, False],
                        default=aws_volume_encryption_config.keep_snapshots,
                        help="True will keep the snapshots after the new disks are created (you will need to clean them"
                             " up).  False will delete them.")

    parser.add_argument('--generate_report', choices=[True, False],
                        default=aws_volume_encryption_config.generate_report,
                        help="True will generate a report at the end.")

    parser.add_argument('--encryption_key_arn',
                        default=aws_volume_encryption_config.encryption_key_arn,
                        help="If you put an encryption key arn here, all disks will be encrypted with that key.")

    parser.add_argument('--force_volume_type',
                        default=aws_volume_encryption_config.force_volume_type,
                        help="If you put a disk type here, all disks will be created with this type.  Default is GP2.")

    parser.add_argument('--instance_ids_list', nargs='*',
                        default=aws_volume_encryption_config.instance_ids,
                        help="Instance Ids that you want to encrypt.")

    parser.add_argument('--instance_names_list', nargs='*',
                        default=aws_volume_encryption_config.instance_names,
                        help="Instance Names that you want to encrypt.")

    parser.add_argument('--use_pool', action='store_true',
                        help="Will attempt to run multiple jobs in parallel.")

    args = parser.parse_args()

    if not args.use_pool:

        if args.instance_ids_list:
            for instance_id in args.instance_ids_list:
                ve = InstanceVolumeEncryptor(_profile=args.profile,
                                             _region=args.region,
                                             _encrypt_all=args.encrypt_all,
                                             _ignore_encrypted=args.ignore_encrypted,
                                             _generate_report=args.generate_report,
                                             _force_volume_type=args.force_volume_type,
                                             _instance_id=instance_id,
                                             _encryption_key_arn=args.encryption_key_arn,
                                             _keep_snapshots=args.keep_snapshots,
                                             _instance_name=None)
                print(ve.encrypt_instance_volumes())

        if args.instance_names_list:
            for instance_name in args.instance_names_list:
                ve = InstanceVolumeEncryptor(_profile=args.profile,
                                             _region=args.region,
                                             _encrypt_all=args.encrypt_all,
                                             _ignore_encrypted=args.ignore_encrypted,
                                             _generate_report=args.generate_report,
                                             _force_volume_type=args.force_volume_type,
                                             _encryption_key_arn=args.encryption_key_arn,
                                             _keep_snapshots=args.keep_snapshots,
                                             _instance_id=None,
                                             _instance_name=instance_name)
                print(ve.encrypt_instance_volumes())

    else:

        # Get master list to work off of.
        master_list = args.instance_ids_list + args.instance_names_list
        worker_list = []

        # Make sure there are names in the list and run a process for each.
        if len(master_list) > 0:

            # Create worker objects with all the settings in place
            for item in master_list:
                worker_list.append(Worker(_profile=args.profile,
                                          _region=args.region,
                                          _encrypt_all=args.encrypt_all,
                                          _ignore_encrypted=args.ignore_encrypted,
                                          _generate_report=args.generate_report,
                                          _force_volume_type=args.force_volume_type,
                                          _encryption_key_arn=args.encryption_key_arn,
                                          _keep_snapshots=args.keep_snapshots,
                                          _instance_unknown=item
                                          ))

            # Setting the max pool size to 5 (you can only do 5 snaps at a time)
            if len(master_list) > 5:
                max_pool_size = 5
            else:
                max_pool_size = len(master_list)

            # Instantiate the tool
            p = Pool(max_pool_size)
            p.map(run, worker_list)

        else:
            print("---Missing list of instance names in config")
