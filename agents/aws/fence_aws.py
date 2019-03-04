#!/usr/bin/python -tt

import sys, re, os
import logging
import atexit
sys.path.append("/usr/share/fence")
from fencing import *
from fencing import fail, fail_usage, EC_TIMED_OUT, run_delay
import boto3
from botocore.exceptions import ClientError, EndpointConnectionError, NoRegionError



fenced_sg_name = "APP_SG_FENCED"
app_sg_name = "APP_SG_live"


def get_filter(name, value):
        filter = [
                {
                        "Name": name,
                        "Values": [value]
                } 
        ]
        return filter


def get_nodes_list(conn, options):    
        result = {}
        try:
                for instance in conn.instances.all():
                        result[next(item for item in instance.tags if item["Key"] == "Name")['Value']] = ("", None)
        except ClientError:
                fail_usage("Failed: Incorrect Access Key or Secret Key.")
        except EndpointConnectionError:
                fail_usage("Failed: Incorrect Region.")
        return result


def get_power_status(conn, options):     
        node_fenced = False
        instance_name = options["--plug"]
        try:
                instances = conn.instances.filter(Filters=get_filter('tag:Name', instance_name))
                instance = list(instances)[0]
                if "--network-fencing" in options:
                        fenced_sg_list = conn.security_groups.filter(Filters=get_filter('group-name', fenced_sg_name))
                        fenced_sg = list(fenced_sg_list)[0]
                        for sg in instance.security_groups:
                                if sg['GroupId'] == fenced_sg.group_id and len(instance.security_groups) == 1:
                                        node_fenced = True

                state = instance.state["Name"]
                
                if state == "running" and not node_fenced:
                        return "on"
                elif state == "stopped" or node_fenced:
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
        instance_name = options["--plug"]
        instances = conn.instances.filter(Filters=get_filter('tag:Name', instance_name))
        instance = list(instances)[0]
	
        if "--network-fencing" in options:
                fenced_sg_list = conn.security_groups.filter(Filters=get_filter('group-name', fenced_sg_name))
                fenced_sg = list(fenced_sg_list)[0]
                app_sg_list = conn.security_groups.filter(Filters=get_filter('group-name', app_sg_name))
                app_sg = list(app_sg_list)[0]
    
        if (options["--action"]=="off") and "--network-fencing" in options:
                instance.modify_attribute(Groups=[fenced_sg.group_id])
                #instance.stop(Force=True)
        elif (options["--action"]=="on") and "--network-fencing" in options:
                instance.modify_attribute(Groups=[app_sg.group_id])
                #instance.start()
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
        docs["longdesc"] = """fence_aws is an I/O Fencing agent for AWS (Amazon Web\
Services). It uses the boto3 library to connect to AWS.\
\n.P\n\
boto3 can be configured with AWS CLI or by creating ~/.aws/credentials.\n\
For instructions see: https://boto3.readthedocs.io/en/latest/guide/quickstart.html#configuration. \n \ 
When using network fencing the reboot-action will cause a quick-return once the network has been fenced \ 
(instead of waiting for the off-action to succeed). \n \
Reboot action will transform to off if network-fencing is on. \n \ 
Attention: Please define fenced_sg_name(sg for fenced nodes) and app_sg_name(regular sg for nodes, \
only one sg to 'on' action supported now) variables as your security group named"""
        docs["vendorurl"] = "http://www.amazon.com"
        show_docs(options, docs)

        run_delay(options)

        if "--network-fencing" in options and options["--action"] == "reboot":
                options["--action"] = "off"

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
