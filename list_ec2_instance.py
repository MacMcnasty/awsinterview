import boto3

session=boto3.Session(profile_name="aws_ec2_iam_user", region="govcloud")

ec2_re=session.resource.(service_name="ec2")

for each_in in ec2_re.instance.all():
    print("each_in.name, each_in.state['Name']")