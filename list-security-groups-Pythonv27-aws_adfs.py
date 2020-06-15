#!/usr/bin/python
import boto.vpc
import os
import sys
import boto.sts
import boto.s3
import requests
import getpass
import ConfigParser
import base64
import logging
import xml.etree.ElementTree as ET
import re
from bs4 import BeautifulSoup
from os.path import expanduser
from urlparse import urlparse, urlunparse

##########################################################################
# Variables
requests.packages.urllib3.disable_warnings()
# region: The default AWS region that this script will connect
# to for all API calls
region = 'us-gov-west-1'

# output format: The AWS CLI output format that will be configured in the
# saml profile (affects subsequent CLI calls)
outputformat = 'json'

# awsconfigfile: The file where this script will store the temp
# credentials under the saml profile
if sys.platform == "linux" or sys.platform == "linux2":
    awsconfigfile = "{0}{1}.aws{1}credentials".format(expanduser("~"), os.path.sep)
else:
    awsconfigfile = 'c:/temp/credentials'

# SSL certificate verification: Whether or not strict certificate
# verification is done, False should only be used for dev/test
sslverification = False

# idpentryurl: The initial url that starts the authentication process.
idpentryurl = 'https://adfs.vmwarefed.com/adfs/ls/IdpInitiatedSignOn.aspx?loginToRp=urn:amazon:webservices:govcloud'

# Uncomment to enable low level debugging
#logging.basicConfig(level=logging.DEBUG)

##########################################################################

def create_dir():
    home_dir = expanduser('~')
    filename = 'credentials'
    print home_dir

    path = home_dir + os.path.sep + '.aws'
    print path
    try:
        if not os.path.exists(path):
            os.mkdir(path)
    except OSError:
        print('Creation of the directory failed')
    else:
        print('Creation of the directory succeeded')
    f = open(os.path.join(path, filename), 'w')
    f.write('[default]\noutput = json\nregion = us-gov-west-1\naws_access_key_id =\naws_secret_access_key =')


def verify_directory_exists(path):
    """
    Make sure that the parent folder/directory for a given file path exists.
    If it doesn't, then create all of the parent folders.
    :param path: absolute path to a file
    """
    directory = os.path.dirname(path)
    if not os.path.exists(directory):
        os.makedirs(directory)



create_dir()
verify_directory_exists(awsconfigfile)

# Get the federated credentials from the user
print "Username:",
username = raw_input()
# TODO: if username doesn't start with "vmwarefed/", should add it automatically
password = getpass.getpass()


# Initiate session handler
session = requests.Session()

# Programmatically get the SAML assertion
# Opens the initial IdP url and follows all of the HTTP302 redirects, and
# gets the resulting login page
formresponse = session.get(idpentryurl, verify=sslverification)
# Capture the idpauthformsubmiturl, which is the final url after all the 302s
idpauthformsubmiturl = formresponse.url

# Parse the response and extract all the necessary values
# in order to build a dictionary of all of the form values the IdP expects
formsoup = BeautifulSoup(formresponse.text.decode('utf8'),features="lxml")
payload = {}

for inputtag in formsoup.find_all(re.compile('(INPUT|input)')):
    name = inputtag.get('name','')
    value = inputtag.get('value','')
    if "user" in name.lower():
        #Make an educated guess that this is the right field for the username
        payload[name] = username
    elif "email" in name.lower():
        #Some IdPs also label the username field as 'email'
        payload[name] = username
    elif "pass" in name.lower():
        #Make an educated guess that this is the right field for the password
        payload[name] = password
    else:
        #Simply populate the parameter with the existing value (picks up hidden fields in the login form)
        payload[name] = value

# Debug the parameter payload if needed
# Use with caution since this will print sensitive output to the screen
#print payload

# Some IdPs don't explicitly set a form action, but if one is set we should
# build the idpauthformsubmiturl by combining the scheme and hostname
# from the entry url with the form action target
# If the action tag doesn't exist, we just stick with the
# idpauthformsubmiturl above
for inputtag in formsoup.find_all(re.compile('(FORM|form)')):
    action = inputtag.get('action')
    loginid = inputtag.get('id')
    if (action and loginid == "loginForm"):
        parsedurl = urlparse(idpentryurl)
        idpauthformsubmiturl = parsedurl.scheme + "://" + parsedurl.netloc + action

# Performs the submission of the IdP login form with the above post data
response = session.post(
    idpauthformsubmiturl, data=payload, verify=sslverification)

# Debug the response if needed
#print (response.text)

# Overwrite and delete the credential variables, just for safety
username = '##############################################'
password = '##############################################'
del username
del password

# Decode the response and extract the SAML assertion
soup = BeautifulSoup(response.text.decode('utf8'), features="lxml")
assertion = ''

# Look for the SAMLResponse attribute of the input tag (determined by
# analyzing the debug print lines above)
for inputtag in soup.find_all('input'):
    if(inputtag.get('name') == 'SAMLResponse'):
        #print(inputtag.get('value'))
        assertion = inputtag.get('value')

# Better error handling is required for production use.
if (assertion == ''):
    #TODO: Insert valid error checking/handling
    print 'Response did not contain a valid SAML assertion'
    sys.exit(0)

# Debug only
# print(base64.b64decode(assertion))

# Parse the returned assertion and extract the authorized roles
awsroles = []
root = ET.fromstring(base64.b64decode(assertion))
for saml2attribute in root.iter('{urn:oasis:names:tc:SAML:2.0:assertion}Attribute'):
    if (saml2attribute.get('Name') == 'https://aws.amazon.com/SAML/Attributes/Role'):
        for saml2attributevalue in saml2attribute.iter('{urn:oasis:names:tc:SAML:2.0:assertion}AttributeValue'):
            awsroles.append(saml2attributevalue.text)

# Note the format of the attribute value should be role_arn,principal_arn
# but lots of blogs list it as principal_arn,role_arn so let's reverse
# them if needed
for awsrole in awsroles:
    chunks = awsrole.split(',')
    if'saml-provider' in chunks[0]:
        newawsrole = chunks[1] + ',' + chunks[0]
        index = awsroles.index(awsrole)
        awsroles.insert(index, newawsrole)
        awsroles.remove(awsrole)

# If I have more than one role, ask the user which one they want,
# otherwise just proceed
print ""
if len(awsroles) > 1:
    i = 0
    print "Please choose the role you would like to assume:"
    for awsrole in awsroles:
        print '[', i, ']: ', awsrole.split(',')[0]
        i += 1
    print "Selection: ",
    selectedroleindex = raw_input()

    # Basic sanity check of input
    if int(selectedroleindex) > (len(awsroles) - 1):
        print 'You selected an invalid role index, please try again'
        sys.exit(0)

    role_arn = awsroles[int(selectedroleindex)].split(',')[0]
    principal_arn = awsroles[int(selectedroleindex)].split(',')[1]
else:
    role_arn = awsroles[0].split(',')[0]
    principal_arn = awsroles[0].split(',')[1]

# Use the assertion to get an AWS STS token using Assume Role with SAML
conn = boto.sts.connect_to_region(region)
token = conn.assume_role_with_saml(role_arn, principal_arn, assertion)

# Write the AWS STS token into the AWS credential file
#home = expanduser("~")
filename = awsconfigfile

# Read in the existing config file
config = ConfigParser.RawConfigParser()
config.read(filename)

# Put the credentials into a saml specific section instead of clobbering
# the default credentials
# section_name = "saml"
section_name = "vidm-prod-gc1"
if not config.has_section(section_name):
    config.add_section(section_name)

config.set(section_name, 'output', outputformat)
config.set(section_name, 'region', region)
config.set(section_name, 'aws_access_key_id', token.credentials.access_key)
config.set(section_name, 'aws_secret_access_key', token.credentials.secret_key)
config.set(section_name, 'aws_session_token', token.credentials.session_token)

# Write the updated config file
with open(filename, 'w+') as configfile:
    config.write(configfile)

# Give the user some basic info as to what has just happened
print '\n\n----------------------------------------------------------------'
print 'Your new access key pair has been stored in the AWS configuration file {0} under the saml profile.'.format(filename)
print 'Note that it will expire at {0}.'.format(token.credentials.expiration)
print 'After this time, you may safely rerun this script to refresh your access key pair.'
print 'To use this credential, call the AWS CLI with the --profile option (e.g. aws --profile {0} ec2 describe-instances).'.format(section_name)
print '----------------------------------------------------------------\n\n'

# YOUR CODE HERE.
# Use the AWS STS token to list all of the S3 buckets

import json
import pprint
import boto3
from sys import argv

ec2 = boto3.client(
                     'ec2',
                     region,
                     aws_access_key_id=token.credentials.access_key,
                     aws_secret_access_key=token.credentials.secret_key,
                     aws_session_token=token.credentials.session_token)

#See if any argument was passed. First argument is the script name, skip that one (-1)
arguments = len(argv) - 1
 
#Explicitly declaring variables here grants them global scope
sgs = ""
cidr_block = ""
ip_protpcol = ""
from_port = ""
to_port = ""
port_range = ""
from_source = ""
 
print("%s,%s,%s,%s,%s,%s" % ("Group-Name","Group-ID","In/Out","Protocol","Port","Source/Destination"))
 
for region in ["us-gov-west-1"]:
        #ec2=boto3.client('ec2', region )
 
        if arguments == 0:
               sgs = ec2.describe_security_groups()["SecurityGroups"]
        else:
               #Filter on passed SG ID
                       sgs = ec2.describe_security_groups(
                               Filters=[
                              {
                              'Name': 'group-id',
                              'Values': [argv[1]]
                              }
                       ]
                       )["SecurityGroups"]
 
        for sg in sgs:
               group_name = sg['GroupName']
               group_id = sg['GroupId']
               print("%s,%s" % (group_name,group_id))
               # InBound permissions ##########################################
               inbound = sg['IpPermissions']
               print("%s,%s,%s" % ("","","Inbound"))
               for rule in inbound:
                       if rule['IpProtocol'] == "-1":
                               traffic_type="All Trafic"
                               ip_protpcol="All"
                               to_port="All"
                       else:
                               ip_protpcol = rule['IpProtocol']
                               from_port=rule['FromPort']
                               to_port=rule['ToPort']
                               if from_port == to_port:
                                      port_range = from_port
                               else:
                                      port_range = str(from_port) + ' - ' + str(to_port)
                               #If ICMP, report "N/A" for port #
                               if to_port == -1:
                                      to_port = "N/A"
 
                       #Is source/target an IP v4?
                       if len(rule['IpRanges']) > 0:
                               for ip_range in rule['IpRanges']:
                                      cidr_block = ip_range['CidrIp']
                                      print("%s,%s,%s,%s,%s,%s" % ("", "", "", ip_protpcol, port_range, cidr_block))
 
                       #Is source/target an IP v6?
                       if len(rule['Ipv6Ranges']) > 0:
                               for ip_range in rule['Ipv6Ranges']:
                                      cidr_block = ip_range['CidrIpv6']
                                      print("%s,%s,%s,%s,%s,%s" % ("", "", "", ip_protpcol, port_range, cidr_block))
 
                       #Is source/target a security group?
                       if len(rule['UserIdGroupPairs']) > 0:
                               for source in rule['UserIdGroupPairs']:
                                      from_source = source['GroupId']
                                      print("%s,%s,%s,%s,%s,%s" % ("", "", "", ip_protpcol, port_range, from_source))
 
               # OutBound permissions ##########################################
               outbound = sg['IpPermissionsEgress']
               print("%s,%s,%s" % ("","","Outbound"))
               for rule in outbound:
                       if rule['IpProtocol'] == "-1":
                               traffic_type="All Trafic"
                               ip_protpcol="All"
                               to_port="All"
                       else:
                               ip_protpcol = rule['IpProtocol']
                               from_port=rule['FromPort']
                               to_port=rule['ToPort']
                               if from_port == to_port:
                                      port_range = from_port
                               else:
                                      port_range = str(from_port) + ' - ' + str(to_port)
                               #If ICMP, report "N/A" for port #
                               if to_port == -1:
                                      to_port = "N/A"
 
                       #Is source/target an IP v4?
                       if len(rule['IpRanges']) > 0:
                               for ip_range in rule['IpRanges']:
                                      cidr_block = ip_range['CidrIp']
                                      print("%s,%s,%s,%s,%s,%s" % ("", "", "", ip_protpcol, port_range, cidr_block))
 
                       #Is source/target an IP v6?
                       if len(rule['Ipv6Ranges']) > 0:
                               for ip_range in rule['Ipv6Ranges']:
                                      cidr_block = ip_range['CidrIpv6']
                                      print("%s,%s,%s,%s,%s,%s" % ("", "", "", ip_protpcol, port_range, cidr_block))
 
                       #Is source/target a security group?
                       if len(rule['UserIdGroupPairs']) > 0:
                               for source in rule['UserIdGroupPairs']:
                                      from_source = source['GroupId']
                                      print("%s,%s,%s,%s,%s,%s" % ("", "", "", ip_protpcol, port_range, from_source))
 




'''
print conn
print 'Simple API example Key:'
print 'access ' + token.credentials.access_key
print 'secret ' + token.credentials.secret_key
print 'done'
'''
