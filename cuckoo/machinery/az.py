# Copyright (C) 2015-2019 Cuckoo Foundation.
# This file is part of Cuckoo Sandbox - http://www.cuckoosandbox.org
# See the file 'docs/LICENSE' for copying permission.
# Originally contributed by Check Point Software Technologies, Ltd. in https://github.com/CheckPointSW/Cuckoo-AWS
# Modified by the Canadian Centre for Cyber Security to support Azure

import logging
import threading
import sys
from datetime import datetime
from pytz import timezone

from cuckoo.common.abstracts import Machinery
from cuckoo.common.config import config
from cuckoo.common.exceptions import CuckooMachineError

from sqlalchemy.exc import SQLAlchemyError

from azure.common.credentials import ServicePrincipalCredentials
from azure.mgmt.compute import ComputeManagementClient
from azure.mgmt.network import NetworkManagementClient
from azure.mgmt.compute.models import DiskCreateOption

log = logging.getLogger(__name__)


class Azure(Machinery):
    """Virtualization layer for Azure."""

    # VM states.
    PENDING = "pending"
    STOPPING = "stopping"
    RUNNING = "running"
    POWEROFF = "poweroff"
    DELETING = "deleting"
    ERROR = "machete"

    AUTOSCALE_CUCKOO = "AUTOSCALE_CUCKOO"
    sys.setrecursionlimit(10000)  # TODO: Arbitrary value for very large JSON results

    def __init__(self):
        super(Azure, self).__init__()

    """override Machinery method"""

    def _initialize_check(self):
        """
        Looking for all machines that match az.conf and load them into AZURE_MACHINES dictionary.
        """
        self.azure_machines = {}
        self.dynamic_machines_sequence = 0
        self.dynamic_machines_count = 0
        self.oldest_machines = []

        try:
            log.debug("Connecting to Azure:{}".format(self.options.az.region_name))
            credentials = self._get_credentials()
            self.network_client = NetworkManagementClient(credentials, self.options.az.subscription_id)
            self.compute_client = ComputeManagementClient(credentials, self.options.az.subscription_id)
        except Exception as e:
            log.error("Exception thrown when setting up Azure Client: %s" % e)

        # Iterate over all instances with tag that has a key of AUTOSCALE_CUCKOO
        try:
            log.debug("Retrieving all virtual machines to find which are autoscaled, if any")
            instances = self.compute_client.virtual_machines.list(self.options.az.group)
        except Exception as e:
            log.error("Failed to retrieve all virtual machines because %s" % e)

        for instance in instances:
            if self._is_autoscaled(instance):
                self._delete_instance(instance.name, initialize=True)

        self._delete_leftover_resources(initialize=True)

        # Stopping or deleting already-running machines
        instance_names = self._list(instances)
        machines = self.machines()
        for machine in machines:
            if machine.label not in instance_names:
                continue
            self.azure_machines[machine.label] = self.compute_client.virtual_machines.get(self.options.az.group,
                                                                                          machine.label)
            if self._status(machine.label) != Azure.POWEROFF:
                self.stop(label=machine.label, initialize=True)

        self._start_or_create_machines(initialize=True)

    def _start_next_machines(self, num_of_machines_to_start):
        """
        pull from DB the next machines in queue and starts them
        the whole idea is to prepare x machines on, so once a task will arrive - the machine will be ready with windows
        already launched.
        :param num_of_machines_to_start: how many machines(first in queue) will be started
        """
        for machine in self.db.get_available_machines():
            if num_of_machines_to_start <= 0:
                break
            if self._status(machine.label) in [Azure.POWEROFF, Azure.STOPPING]:
                # not using self.start() to avoid _wait_ method
                self.compute_client.virtual_machines.start(self.options.az.group, machine.label)
                num_of_machines_to_start -= 1

    def _delete_machine_form_db(self, label):
        """
        cuckoo's DB class does not implement machine deletion, so we made one here
        :param label: the machine label
        """
        session = self.db.Session()
        try:
            from cuckoo.core.database import Machine
            machine = session.query(Machine).filter_by(label=label).first()
            if machine:
                session.delete(machine)
                session.commit()
        except SQLAlchemyError as e:
            log.debug("Database error removing machine: {0}".format(e))
            session.rollback()
            return
        finally:
            session.close()

    def _allocate_new_machine(self):
        """
        allocating/creating new Azure VM(autoscale option)
        """
        # read configuration file
        machinery_options = self.options.get("az")
        autoscale_options = self.options.get("autoscale")
        # If configured, use specific network interface for this
        # machine, else use the default value.
        interface = autoscale_options.get("interface") if autoscale_options.get("interface") else machinery_options.get(
            "interface")
        resultserver_ip = autoscale_options.get("resultserver_ip") if autoscale_options.get("resultserver_ip") \
            else config("cuckoo:resultserver:ip")
        if autoscale_options.get("resultserver_port"):
            resultserver_port = autoscale_options.get("resultserver_port")
        else:
            # The ResultServer port might have been dynamically changed,
            # get it from the ResultServer singleton. Also avoid import
            # recursion issues by importing ResultServer here.
            from cuckoo.core.resultserver import ResultServer
            resultserver_port = ResultServer().port

        self.dynamic_machines_sequence += 1
        new_machine_name = "vmcuckooguest%03d" % self.dynamic_machines_sequence

        # Avoiding collision on machine name if machine is still deleting
        instances = self.compute_client.virtual_machines.list(self.options.az.group)
        instance_names = self._list(instances)
        for instance in instance_names:
            while instance == new_machine_name:
                self.dynamic_machines_sequence = self.dynamic_machines_sequence + 1
                new_machine_name = "vmcuckooguest%03d" % self.dynamic_machines_sequence

        new_machine_nic = self._create_nic("nic-01", new_machine_name, self.options.az.cuckoo_subnet, resultserver_ip)

        # for some reason Azure cannot create multiple NICs in parallel, this clause is to prevent errors being thrown
        if new_machine_nic is None:
            self.dynamic_machines_count -= 1
            return False

        nics = [new_machine_nic]
        try:
            guest_instance = self._create_instance(
                nics,
                tags={'Name': new_machine_name, self.AUTOSCALE_CUCKOO: True}
            )
        except Exception as e:
            log.error("Attempted to create {0} but was interrupted by {1}".format(new_machine_name, e))
            self.dynamic_machines_count -= 1
            return False

        if guest_instance is None:
            self.dynamic_machines_count -= 1
            return False

        log.info("Allocating a new machine %s to meet pool size requirements" % new_machine_name)
        self.oldest_machines.append(new_machine_name)
        self.azure_machines[new_machine_name] = guest_instance
        #  sets "new_machine" object in configuration object to avoid raising an exception
        setattr(self.options, new_machine_name, {})
        # add machine to DB
        self.db.add_machine(
            name=new_machine_name,
            label=new_machine_name,
            ip=new_machine_nic.ip_configurations[0].private_ip_address,
            platform=autoscale_options.get("platform"),
            options=autoscale_options.get("options"),
            tags=autoscale_options["tags"],
            interface=interface,
            snapshot=autoscale_options.get("guest_snapshot"),
            resultserver_ip=resultserver_ip,
            resultserver_port=resultserver_port
        )
        return True

    """override Machinery method"""

    def acquire(self, machine_id=None, platform=None, tags=None):
        """
        override Machinery method to utilize the auto scale option
        """
        # Used to minimize wait times as VMs are starting up and not ready to listen yet
        if not self.oldest_machines:
            machine_id = self.oldest_machines.pop(0)
        base_class_return_value = super(Azure, self).acquire(machine_id, platform, tags)
        self._start_or_create_machines()  # prepare another machine
        return base_class_return_value

    def _start_or_create_machines(self, initialize=False):
        """
        checks if x(according to "gap" in az config) machines can be immediately started.
        If autoscale is enabled and less then x can be started - > create new instances to complete the gap
        :param initialize: Flag to determine if we should wait for all machines to finish being created
        :return:
        """

        # read configuration file
        machinery_options = self.options.get("az")
        autoscale_options = self.options.get("autoscale")

        current_available_machines = self.db.count_machines_available()
        running_machines_gap = machinery_options.get("running_machines_gap", 0)
        dynamic_machines_limit = autoscale_options["dynamic_machines_limit"]
        self._start_next_machines(num_of_machines_to_start=min(current_available_machines, running_machines_gap))
        #  if no sufficient machines left  -> launch a new machines
        threads = []
        while autoscale_options.get("autoscale") and current_available_machines < running_machines_gap:
            if self.dynamic_machines_count >= dynamic_machines_limit:
                log.debug("Reached dynamic machines limit - %d machines" % dynamic_machines_limit)
                break
            else:
                # Using threads to create machines in parallel
                self.dynamic_machines_count += 1
                thr = threading.Thread(target=self._allocate_new_machine)
                threads.append(thr)
                thr.start()
                current_available_machines += 1

        # Waiting for all machines to finish being created
        if initialize:
            for thr in threads:
                thr.join()

    """override Machinery method"""

    def _list(self, instances):
        """
        :return: A list of all instance ids under the az account
        """
        return [instance.name for instance in instances]

    """override Machinery method"""

    def _status(self, label):
        """
        Gets current status of a vm.
        @param label: virtual machine label.
        @return: status string.
        """
        try:
            instance = self.compute_client.virtual_machines.get(self.options.az.group, label, expand='instanceView')

            if len(instance.instance_view.statuses) > 1:
                state = instance.instance_view.statuses[1].code
            else:
                state = instance.instance_view.statuses[0].code

            if state == "PowerState/running":
                status = Azure.RUNNING
            elif state == "PowerState/stopped":
                status = Azure.POWEROFF
            elif state == "PowerState/starting":
                status = Azure.PENDING
            elif state == "PowerState/stopping":
                status = Azure.STOPPING
            elif state == "PowerState/deallocating":
                status = Azure.STOPPING
            elif state == "PowerState/deallocated":
                status = Azure.POWEROFF
            elif state == "ProvisioningState/deleting":
                status = Azure.DELETING
            elif state in [
                "ProvisioningState/creating",
                "ProvisioningState/updating",
                "ProvisioningState/deleting",
                "ProvisioningState/failed/InternalOperationError",
                "ProvisioningState/creating/OSProvisioningInprogress",
                "ProvisioningState/creating/OSProvisioningComplete"
            ]:
                status = Azure.ERROR
            else:
                status = Azure.ERROR
            return status
        except Exception as e:
            log.exception("can't retrieve the status: {}".format(e))
            return Azure.ERROR

    """override Machinery method"""

    def start(self, label, task):
        """
        Start a virtual machine.
        @param label: virtual machine label.
        @param task: task object.
        @raise CuckooMachineError: if unable to start.
        """
        log.debug("Starting vm {}".format(label))

        if not self._is_autoscaled(self.azure_machines.get(label)):
            self.compute_client.virtual_machines.start(self.options.az.group, label)
            self._wait_status(label, Azure.RUNNING)

    """override Machinery method"""

    def stop(self, label, initialize=False):
        """
        Stops a virtual machine.
        If the machine has initialized from autoscaled component, then terminate it.
        @param label: virtual machine label.
        @raise CuckooMachineError: if unable to stop.
        :param initialize:
        """
        log.debug("Stopping vm %s" % label)

        status = self._status(label)

        if status == Azure.POWEROFF:
            raise CuckooMachineError(
                "Trying to stop an already stopped VM: %s" % label
            )

        if self._is_autoscaled(self.azure_machines.get(label)):
            self._delete_instance(label, initialize=initialize)
        else:
            self.compute_client.virtual_machines.deallocate(self.options.az.group, label)
            self._wait_status(label, Azure.POWEROFF)
            self._restore(label)

        self._delete_leftover_resources()

    """override Machinery method"""

    def release(self, label=None):
        """
        we override it to have the ability to run start_or_create_machines() after unlocking the last machine
        Release a machine.
        @param label: machine label.
        """
        super(Azure, self).release(label)
        self._start_or_create_machines()

    def _create_instance(self, nics, tags):
        """
        create a new instance
        :param nics: network interface cards to be attached to guest VM
        :param tags: tags to attach to instance
        :return: the instance id
        """

        autoscale_options = self.options.get("autoscale")
        computer_name = tags.get('Name')

        new_disk = self._create_disk_from_snapshot(autoscale_options.get('guest_snapshot'), computer_name)
        os_disk = {
            'create_option': 'Attach',
            'managed_disk': {
                'id': new_disk.id,
                'storage_account_type': autoscale_options.get('storage_account_type')
            },
            'osType': autoscale_options.get('platform')
        }

        vm_parameters = {
            'location': self.options.az.region_name,
            'tags': tags,
            'properties': {
                'hardwareProfile': {
                    'vmSize': autoscale_options.instance_type
                },
                'storageProfile': {
                    'osDisk': os_disk
                }
            },
            'networkProfile': {
                'networkInterfaces': [{
                    'id': nics[0].id,
                    'properties': {'primary': True}
                }]
            }
        }
        async_vm_creation = self.compute_client.virtual_machines.create_or_update(
            self.options.az.group,
            computer_name,
            vm_parameters
        )
        # async_vm_creation.wait()
        new_instance = async_vm_creation.result()
        log.debug("Created %s\n%s", new_instance.id, repr(new_instance))
        return new_instance

    def _is_autoscaled(self, instance):
        """
        checks if the instance has a tag that indicates that it was created as a result of autoscaling
        :param instance: instance object
        :return: true if the instance in "autoscaled"
        """
        if instance.tags and instance.tags.get(self.AUTOSCALE_CUCKOO) == 'True':
            return True
        return False

    def _restore(self, label):
        """
        restore the instance according to the configured snapshot(az.conf)
        This method creates a new OS disk from a snapshot, detaches the current OS disk, attaches the new OS disk,
        then deletes the old disk
        :param label: machine label
        """
        log.debug("restoring machine: {}".format(label))
        vm_info = self.db.view_machine_by_label(label)
        snapshot = self.compute_client.snapshots.get(self.options.az.group, vm_info.snapshot)
        snap_id = snapshot.id
        instance = self.azure_machines.get(label)
        state = self._status(label)
        if state != Azure.POWEROFF:
            raise CuckooMachineError(
                 "Instance '%s' state '%s' is not poweroff" % (label, state)
            )

        new_disk = self._create_disk_from_snapshot(snap_id, label)

        log.debug("Swapping OS disk on vm '%s'" % label)
        instance.storage_profile.os_disk = {
            'create_option': instance.storage_profile.os_disk.create_option,
            'managed_disk': {
                'id': new_disk.id
            }
        }

        log.debug("Updating VM '%s' with new OS disk" % label)
        self.compute_client.virtual_machines.create_or_update(
            self.options.az.group,
            instance.name,
            parameters=instance
        )

    def _get_credentials(self):
        """
        Used to create the Azure Credentials object
        """
        credentials = ServicePrincipalCredentials(
            client_id=self.options.az.client_id,
            secret=self.options.az.secret,
            tenant=self.options.az.tenant
        )
        return credentials

    def _create_nic(self, nic_name, computer_name, subnet, dns_server):
        """
        Used to create the Azure network interface card
        :param network_client: Azure NetworkManagementClient
        :param nic_name: name of the new nic
        :param computer_name: name of VM that nic is going to be attached to
        :param subnet: name of subnet that nic will connect to
        :param dns_server: name of server that DNS resolution will take place
        """
        subnet_info = self.network_client.subnets.get(
            self.options.az.group,
            self.options.az.vnet,
            subnet
        )
        nic_params = {
            'location': self.options.az.region_name,
            'ip_configurations': [{
                'name': 'myIPConfig',
                'subnet': {
                    'id': subnet_info.id
                }
            }],
            'dns_settings': {
                'dns_servers': [dns_server]
            }
        }
        nic_name = nic_name + "-" + computer_name
        try:
            async_nic_creation = self.network_client.network_interfaces.create_or_update(
                self.options.az.group,
                nic_name,
                nic_params
            )
            async_nic_creation.wait()
            nic = async_nic_creation.result()
            return nic
        except Exception as e:
            log.error("NIC %s was not created due to %s" % (nic_name, e))
            return None

    def _delete_leftover_resources(self, initialize=False):
        # Iterate over all network interface cards to check if any are not associated to a VM
        nics = None
        try:
            log.debug("Listing all network interface cards")
            nics = self.network_client.network_interfaces.list(self.options.az.group)
        except Exception as e:
            log.error("Failed to list network interface cards because %s" % e)

        threads = []
        for nic in nics:
            if nic.tags and nic.virtual_machine is None and nic.tags.get('status', '') == 'to_be_deleted':
                try:
                    log.debug("Deleting leftover network interface card %s" % nic.name)
                    async_delete_nic = self.network_client.network_interfaces.delete(self.options.az.group, nic.name)
                except Exception as e:  # CloudError
                    print(nic)
                    log.error("Attempted to delete {0} but was interrupted by {1}".format(nic.name, e))
                    continue

                if initialize:
                    thr = threading.Thread(target=async_delete_nic.wait)
                    threads.append(thr)
                    thr.start()

        if initialize:
            for thr in threads:
                # Need to wait for each network interface card to delete during initialization
                thr.join()

        # Iterate over all OS disks to check if any are not associated to a VM
        disks = None
        try:
            log.debug("Listing all managed disks")
            disks = self.compute_client.disks.list_by_resource_group(self.options.az.group)
        except Exception as e:
            log.error("Failed to list managed disks because %s" % e)

        for disk in disks:
            time_delta = datetime.now() - disk.time_created.replace(tzinfo=None)
            # If the disk is unattached and has been around for one minute, then the disk can be deleted
            if disk.disk_state == "Unattached" and time_delta.total_seconds() > 180:
                try:
                    log.debug("Deleting leftover managed disk %s" % disk.name)
                    self.compute_client.disks.delete(self.options.az.group, disk.name)
                except Exception as e:  # CloudError
                    print(disk)
                    log.error("Attempted to delete {0} but was interrupted by {1}".format(disk.name, e))
                    continue

        # Iterate over all instances to check if they're deployment Failed
        instances = self.compute_client.virtual_machines.list(self.options.az.group)
        for instance in instances:
            if instance.provisioning_state == "Failed":
                log.debug("Deleting instance that failed to deploy %s" % instance.name)
                self._delete_instance(instance.name, initialize=initialize)

    def _create_disk_from_snapshot(self, snapshot_name, new_computer_name):
        log.debug("Creating disk which is a copy of a snapshot")
        snapshot = None

        try:
            log.debug("Retrieving the snapshot to be used to create victim disks")
            snapshot = self.compute_client.snapshots.get(self.options.az.group, snapshot_name)
        except Exception as e:
            log.error("Failed to retrieve the snapshot {0} because {1}".format(snapshot_name, e))

        snap_id = snapshot.id
        new_disk_name = "osdisk" + new_computer_name

        try:
            log.debug("Creating a managed disk using the snapshot")
            async_disk_creation = self.compute_client.disks.create_or_update(
                self.options.az.group,
                new_disk_name,
                {
                    'location': self.options.az.region_name,
                    'creation_data': {
                        'create_option': DiskCreateOption.copy,
                        'source_uri': snap_id
                    }
                }
            )
        except Exception as e:
            log.error("Failed to create a managed disk because %s" % e)

        try:
            log.debug("Polling the status of the creation of the managed disk")
            async_disk_creation.wait()
        except Exception as e:
            log.error("Failed to poll the status of the creation of the managed disk because %s" % e)

        return async_disk_creation.result()

    def _delete_instance(self, instance_name, initialize=False):
        try:
            log.debug("Marking instance NIC to be deleted")
            self.network_client.network_interfaces.update_tags(self.options.az.group, "nic-01-" + instance_name,
                                                               tags={'status': 'to_be_deleted'})
        except Exception as e:
            log.error("Failed to mark {0} because {1}".format("nic-01-" + instance_name, e))

        try:
            log.info("Terminating autoscaling instance %s" % instance_name)
            self.compute_client.virtual_machines.delete(self.options.az.group, instance_name)

            if not initialize:
                del self.azure_machines[instance_name]
                self._delete_machine_form_db(instance_name)
                self.dynamic_machines_count -= 1
        except Exception as e:
            log.error("Failed to delete instance {0} because {1}".format(instance_name, e))

