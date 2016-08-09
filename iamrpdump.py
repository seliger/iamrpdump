#!/usr/bin/env python

import boto3, botocore, json, sys, time, shutil, os, glob, argparse, logging, datetime, re

JSON_INDENT = 2
AWS_CREDENTIAL_PROFILE="default"
AWS_SLEEP_INTERVAL = 10 #seconds
LOCAL_SLEEP_INTERVAL = 1 #seconds
ARPD_FILE = "AssumeRolePolicyDocument.json"
ACCOUNT_FILE = "src_account_number.txt"
POLICY_DIR = "policies"
MAX_RETRY = 6
LOG_LEVEL = "INFO"
DUMP_PATH = "dump"
THREAD_START_DELAY = 1 #seconds
CURRENT_WORKING_DIR = os.getcwd()
DEFAULT_PREFIX_SEPARATOR = "-"


def mkdir_p(path):
  try:
    os.makedirs(path)
  except OSError as exc:
    if exc.errno == errno.EEXIST and os.path.isdir(path):
      pass
    else: raise


def get_aws_account_number(ec2_client):
	# Reference: http://stackoverflow.com/questions/30656618/aws-powershell-to-retrieve-aws-account-number
	sg_list = []

	sg_data = ec2_client.describe_security_groups(GroupNames=["default"])
	sg_list.extend(sg_data["SecurityGroups"])

	return sg_list[0]["OwnerId"]


def get_stored_aws_account_number():
	account_file_name = CURRENT_WORKING_DIR + "/" + DUMP_PATH + "/" + ACCOUNT_FILE
	account_file = open(account_file_name)

	try:
		account_number = account_file.read()
	except IOError:
		logging.error("Could not retrieve the original source account number in " + account_file_name)
		sys.exit(1)
	
	account_file.close()

	return account_number


def get_remote_role_dict(iam_client):
	role_list = []
	role_dict = {}

	logging.info("Enumerating list of IAM Roles...")
	roles_data = iam_client.list_roles()
	role_list.extend(roles_data["Roles"])

	for role in role_list:
		role_dict[role["RoleName"]] = role

	return role_dict

def get_local_role_list():
	roles_dir = CURRENT_WORKING_DIR + "/" + DUMP_PATH
	return filter(lambda x: os.path.isdir(os.path.join(roles_dir, x)), os.listdir(roles_dir))

def get_role_policies_list(iam_client, role_name):
	rp_list = []

	logging.info("Enumerating list of policies for role " + role_name)

	rp_data = iam_client.list_role_policies(RoleName=role_name)
	rp_list.extend(rp_data["PolicyNames"])

	return rp_list


def get_role_policy(iam_client, role_name, policy_name):
	policy_doc = iam_client.get_role_policy(RoleName=role_name, PolicyName=policy_name)

	return policy_doc


def do_export_account_number(ec2_client):
	logging.info("Writing account number to " + ACCOUNT_FILE)
	f = open(CURRENT_WORKING_DIR + "/" + DUMP_PATH + "/" + ACCOUNT_FILE, "w+")
	f.write(get_aws_account_number(ec2_client) + "\n")
	f.close()


def do_export_role(client, role_dict, role_name):

	# Create new tree
	mkdir_p(CURRENT_WORKING_DIR + "/" + DUMP_PATH + "/" + role_name)
	mkdir_p(CURRENT_WORKING_DIR + "/" + DUMP_PATH + "/" + role_name + "/" + POLICY_DIR)

	# Dump out the Assumed Role Policy Document
	logging.info("Exporting AssumeRole Policy Document for role " + role_name)
	f = open(CURRENT_WORKING_DIR + "/" + DUMP_PATH + "/" + role_name + "/" + ARPD_FILE, "w+")
	f.write(json.dumps(role_dict[role_name]["AssumeRolePolicyDocument"], indent=JSON_INDENT))
	f.close()

	# Look up the associated policies and dump those out to a set of files
	for policy_name in get_role_policies_list(client, role_name):
		logging.info("Exporting policy document " + policy_name + " for role " + role_name)
		policy_doc = get_role_policy(client, role_name, policy_name)
		f = open(CURRENT_WORKING_DIR + "/" + DUMP_PATH + "/" + role_name + "/" + POLICY_DIR + "/" + policy_name + ".json", "w+")
		f.write(json.dumps(policy_doc, indent=JSON_INDENT))
		f.close()


def do_import_role(iam_client, role_name):
	role_path = CURRENT_WORKING_DIR + "/" + DUMP_PATH + "/" + role_name
	try:
		logging.info("Loading AssumeRolePolicyDocument for role " + role_name)
		arpd = json.load(open(role_path + "/" + ARPD_FILE))
	except IOError as e:
		logging.error("Error accessing \"" + role_path + "/" + ARPD_FILE + "\" Cannot import role " + role_name)
		return

	logging.info("Creating role " + role_name)
	try:
		iam_client.create_role(RoleName=role_name, Path="/", AssumeRolePolicyDocument=json.dumps(arpd, indent=JSON_INDENT))
	except botocore.exceptions.ClientError as e:
		if e.response["Error"]["Code"] == "EntityAlreadyExists":
			logging.warn("Role " + role_name + " already existed")
		else:
#			logging.error("Creating role " + role_name + " caused an exception on the backend; status code: " + e.response["ResponseMetadata"]["HTTPStatusCode"])
			logging.error("Creating role {} caused an exception on the backend; status code: {}".format(role_name, e.response["ResponseMetadata"]["HTTPStatusCode"]))
			logging.error(e.response["Error"]["Message"])



def do_import_role_policies(iam_client, role_name, target_account_number):
	role_path = CURRENT_WORKING_DIR + "/" + DUMP_PATH + "/" + role_name
	policy_path = role_path + "/" + POLICY_DIR

	policy_file_list = glob.glob(policy_path + "/*.json")

	if len(policy_file_list) > 0:
		for policy_file_name in policy_file_list:
			logging.info("Loading policy file " + policy_file_name + " for role " + role_name)
			policy_file = open(policy_file_name)
			policy_raw = policy_file.read()
			policy_file.close()

			policy_edited = re.sub(str(get_stored_aws_account_number()).rstrip(), target_account_number, policy_raw)

			policy = json.loads(policy_edited) 
			policy_name = policy["PolicyName"]

			logging.info("Attaching policy " + policy["PolicyName"] + " to role " + role_name)
			try:
				iam_client.put_role_policy(RoleName=role_name, PolicyName=policy_name, PolicyDocument=json.dumps(policy["PolicyDocument"], indent=JSON_INDENT))
			except botocore.exceptions.ClientError as e:
				if e.response["Error"]["Code"] == "EntityAlreadyExists":
					logging.warn("Policy " + policy["PolicyName"] + " already existed for role " + role_name)
				else:
					logging.error("Attaching policy {} to role {} caused an exception on the backend; status code: {}".format(policy["PolicyName"], role_name, e.response["ResponseMetadata"]["HTTPStatusCode"]))
					logging.error(e.response["Error"]["Message"])
					raise

	else:
		logging.warn("No policies were found for role " + role_name + ". No policies imported.")


def do_import(iam_client, ec2_client):
	if not os.path.exists(CURRENT_WORKING_DIR + "/" + DUMP_PATH):
		logging.error(CURRENT_WORKING_DIR + "/" + DUMP_PATH + " does not exist. Cannot proceed.")
		sys.exit(1)

	# Get the target account number (the one we are shooting for)
	target_account_number = get_aws_account_number(ec2_client)

	# Iterate through the roles and import them
	for role_name in get_local_role_list():
		do_import_role(iam_client, role_name)
		do_import_role_policies(iam_client, role_name, target_account_number)

def do_export(iam_client, ec2_client):

	# Check to see if our target directory exists. If so, bail.
	if os.path.exists(CURRENT_WORKING_DIR + "/" + DUMP_PATH):
		logging.error(CURRENT_WORKING_DIR + "/" + DUMP_PATH + " already exists. Remove it before trying to do another export.")
		sys.exit(1)

	# Make our base directory
	mkdir_p(CURRENT_WORKING_DIR + "/" + DUMP_PATH)	

	# Pull in our source account number and store it
	do_export_account_number(ec2_client)

	# Gather dictionary of roles
	role_dict = get_remote_role_dict(iam_client)

	# Iterate through the roles and export them
	for role_name in role_dict:
		do_export_role(iam_client, role_dict, role_name)

##### Main routine starts here.

### Set up environment based on CLI arguments
parser = argparse.ArgumentParser(description="Simple IAM role policy export/import utility.")
parser.add_argument("-m", "--mode", help="'export' or 'import'")
parser.add_argument("-p", "--profile", default="default", help="AWS profile name to use. Allows to you to choose alternate profile from your AWS credentials file.")
parser.add_argument("--log", help="Logging level - DEBUG|INFO|WARNING|ERROR|CRITICAL [optional]")
args = parser.parse_args()

if args.mode == None:
	logging.error("Argument -m (export|import) required")
	sys.exit(1)

# set log level
log_level = LOG_LEVEL
if args.log != None:
	log_level = args.log.upper()
logging.basicConfig(level=getattr(logging, log_level))


### Bootstrap the AWS envioronment
# Set the AWS credentials profile
AWS_CREDENTIAL_PROFILE=args.profile

# Reference: https://boto3.readthedocs.io/en/latest/reference/core/session.html
logging.info("Setting up the boto3 session...")
aws_session = boto3.session.Session(profile_name=AWS_CREDENTIAL_PROFILE)

# Initialize our AWS clients
logging.info("Configuring the IAM client...")
iam_client = aws_session.client("iam")
logging.info("Configuring the EC2 client...")
ec2_client = aws_session.client("ec2")


if args.mode == "export":
	logging.info("Starting do_export...")
	do_export(iam_client, ec2_client)
elif args.mode == "import":
	logging.info("Starting do_import...")
	do_import(iam_client, ec2_client)


### EOF