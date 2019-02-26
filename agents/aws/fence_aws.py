#!/usr/bin/python -tt

import sys, re, os
import logging
import atexit
sys.path.append("/usr/share/fence")
from fencing import *
from fencing import fail, fail_usage, EC_TIMED_OUT, run_delay

import boto3
from botocore.exceptions import ClientError, EndpointConnectionError, NoRegionError


fenced_sg_name = "deny-all"
app_sg_name = "APP_SG_live"

def get_nodes_list(conn, options):
        result = {}
        try:
                for instance in conn.instances.all():
                        result[instance.id] = ("", None)
        except ClientError:
                fail_usage("Failed: Incorrect Access Key or Secret Key.")
        except EndpointConnectionError:
                fail_usage("Failed: Incorrect Region.")
        return result


def get_power_status(conn, options):
	node_fenced = False
	try:
		instance = list(conn.instances.filter(Filters=[{"Name": "tag:Name", "Values": [options["--plug"]]}]))[0]
		if "--network-fencing" in options:
			fenced_sg = list(conn.security_groups.filter(Filters=[{"Name": "group-name", "Values": [fenced_sg_name]}]))[0]
			print('Check node by ping...')
			ping_response = True if os.system("ping -c 5 " + instance.private_ip_address) is 0 else False
			for sg in instance.security_groups:
				if sg['GroupId'] == fenced_sg.group_id:
					node_fenced = True
		
		state = instance.state["Name"]
		if "--network-fencing" in options and state == "running" and ping_response is True and not node_fenced:
			return "on"
		elif "--network-fencing" not in options and state == "running":
			return "on"
		elif state == "stopped" or (ping_response is False and node_fenced):
			return "off"
		else:
			return "unknown"

	except ClientError:
		fail_usage("Failed: Incorrect Access Key or Secret Key.")
	except EndpointConnectionError:
		fail_usage("Failed: Incorrect Region.")
	except IndexError:
		return "fail"

def set_power_status(conn, options):
	instance = list(conn.instances.filter(Filters=[{"Name": "tag:Name", "Values": [options["--plug"]]}]))[0]
	if "--network-fencing" in options:
		fenced_sg = list(conn.security_groups.filter(Filters=[{"Name": "group-name", "Values": [fenced_sg_name]}]))[0]
		app_sg = list(conn.security_groups.filter(Filters=[{"Name": "group-name", "Values": [app_sg_name]}]))[0]
    
	if (options["--action"]=="off") and "--network-fencing" in options:
		instance = list(conn.instances.filter(Filters=[{"Name": "tag:Name", "Values": [options["--plug"]]}]))[0]
		print('Move instance to fenced_sg...')
		instance.modify_attribute(Groups=[fenced_sg.group_id])
		print('Stopping instance...')
		instance.stop(Force=True)
	elif (options["--action"]=="on") and "--network-fencing" in options:
		print('Move instance to app_sg...')
		instance.modify_attribute(Groups=[app_sg.group_id])
		print('Starting instance...')
		instance.start()
	elif (options["--action"]=="off"):
		instance.stop(Force=True)
	elif (options["--action"]=="on"):
		instance.start()


def define_new_opts():
        all_opt["region"] = {
                "getopt" : "r:",
                "longopt" : "region",
                "help" : "-r, --region=[name]            Region, e.g. us-east-1",
                "shortdesc" : "Region.",
                "required" : "0",
                "order" : 2
        }
        all_opt["access_key"] = {
                "getopt" : "a:",
                "longopt" : "access-key",
                "help" : "-a, --access-key=[name]         Access Key",
                "shortdesc" : "Access Key.",
                "required" : "0",
                "order" : 3
        }
        all_opt["secret_key"] = {
                "getopt" : "s:",
                "longopt" : "secret-key",
                "help" : "-s, --secret-key=[name]         Secret Key",
                "shortdesc" : "Secret Key.",
                "required" : "0",
                "order" : 4
        }
        all_opt["network-fencing"] = {
                "getopt" : "",
                "longopt" : "network-fencing",
                "help" : "--network-fencing: enable moving the instance to special security group",
                "shortdesc" : "turn on sg fencing",
                "required" : "0",
                "order" : 5
        }

# Main agent method
def main():
        conn = None

        device_opt = ["port", "no_password", "region", "access_key", "secret_key", "network-fencing"]

        atexit.register(atexit_handler)

        define_new_opts()
        #This should be longer then reboot/off timeout in pacemaker
        all_opt["power_timeout"]["default"] = "600"

        options = check_input(device_opt, process_input(device_opt))

        docs = {}
        docs["shortdesc"] = "Fence agent for AWS (Amazon Web Services)"
        docs["longdesc"] = "fence_aws is an I/O Fencing agent for AWS (Amazon Web\
Services). It uses the boto3 library to connect to AWS.\
\n.P\n\
boto3 can be configured with AWS CLI or by creating ~/.aws/credentials.\n\
For instructions see: https://boto3.readthedocs.io/en/latest/guide/quickstart.html#configuration"
        docs["vendorurl"] = "http://www.amazon.com"
        show_docs(options, docs)

        run_delay(options)

        if "--region" in options and "--access-key" in options and "--secret-key" in options:
                region = options["--region"]
                access_key = options["--access-key"]
                secret_key = options["--secret-key"]
                try:
                        conn = boto3.resource('ec2', region_name=region,
                                              aws_access_key_id=access_key,
                                              aws_secret_access_key=secret_key)
                except:
                        fail_usage("Failed: Unable to connect to AWS. Check your configuration.")
        else:
                # If setup with "aws configure" or manually in
                # ~/.aws/credentials
                try:
                        conn = boto3.resource('ec2')
                except:
                        # If any of region/access/secret are missing
                        fail_usage("Failed: Unable to connect to AWS. Check your configuration.")

        # Operate the fencing device
        result = fence_action(conn, options, set_power_status, get_power_status, get_nodes_list)
        sys.exit(result)

if __name__ == "__main__":
        main()
