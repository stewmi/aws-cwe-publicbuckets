# -*- coding: utf-8 -*-
"""Public Read/Write Bucket Remediation

This Lambda function will listen, using CloudWatch Events, to a Config rule that
is triggered to be non-compliant if a public-read or public-write policy is found.

Once a Non-Compliant Bucket is found,  it will add a private bucket acl to the bucket
and then message the bucket policy, if found, to an SNS topic that administrators
can subscribe to.

"""
<<<<<<< HEAD
=======
# Copyright 2017 Amazon.com, Inc. or its affiliates. All Rights Reserved.
#
# Licensed under the Apache License, Version 2.0 (the "License"). You may not
# use this file except in compliance with the License. A copy of the License
# is located at
#
#     http://aws.amazon.com/apache2.0/
#
# or in the "license" file accompanying this file. This file is distributed on
# an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either
# express or implied. See the License for the specific language governing
# permissions and limitations under the License.
>>>>>>> 40323cc7740e2de2b8eed6a4642b956c55a0a02b
import boto3
from botocore.exceptions import ClientError
import json
import os
import logging

ACL_RD_WARNING = "The S3 bucket ACL allows public read access."
PLCY_RD_WARNING = "The S3 bucket policy allows public read access."
ACL_WRT_WARNING = "The S3 bucket ACL allows public write access."
PLCY_WRT_WARNING = "The S3 bucket policy allows public write access."
RD_COMBO_WARNING = ACL_RD_WARNING + PLCY_RD_WARNING
WRT_COMBO_WARNING = ACL_WRT_WARNING + PLCY_WRT_WARNING

TOPIC_ARN = os.environ['TOPIC_ARN']

s3 = boto3.client('s3')
sns = boto3.client('sns')
logger = logging.getLogger()
logger.setLevel(logging.INFO)

def get_policy(bucket_name):
    """Looks up a bucket's bucket policy and returns if found.

    Args:
        bucket_name (str): The Name of a S3 Bucket within the account.

    Returns:
        str: The Bucket Policy if found.
    """
    try:
        bucket_policy = s3.get_bucket_policy(Bucket=bucket_name)
        return bucket_policy
    except ClientError as e:
        # error caught due to no bucket policy
        logger.error("No bucket policy found; no alert sent.")
        logger.error(e)
        return "No Bucket Policy Found."

def policy_notifier(bucket_name, subject, message):
    """Looks up a bucket's bucket policy and returns if found.

    Args:
        bucket_name (str):  The Name of a S3 Bucket within the account.
        subject (str):      The Subject for the message.
        message (str):      The body of the message.

    Returns:
        bool: returns True if message sent.
    """
    try:
        response = sns.publish(
            TopicArn=TOPIC_ARN,
            Subject=subject,
            Message=message
        )
        if response['MessageId'] is not None:
            return True
        return False
    except Exception as e:
        return False
    logger.info("Message Sent: %s", message)
    logger.debug(response)

def lambda_handler(event, context):
    """Main handler for the lambda function.

    Args:
        event (str):    The Event.
        context (str):  The Context.

    Returns:
        None: This function does not return a value.
    """
    try:
        logger.info(event)
        bucket_name = event['detail']['resourceId']
        compliance_failure = event['detail']['newEvaluationResult']['annotation']
        logger.info("bucket name: %s", bucket_name)
        subject = "Compliance Failure: %s" % bucket_name
        bucket_policy = get_policy(bucket_name)

        if (compliance_failure == ACL_RD_WARNING or compliance_failure == PLCY_RD_WARNING):
            s3.put_bucket_acl(Bucket=bucket_name, ACL='private')
            message = "Public Readable Bucket Found: %s. ACL Reverted.  Review Policy: %s" % (bucket_name, bucket_policy)
            policy_notifier(bucket_name, subject, message)
        elif (compliance_failure == PLCY_RD_WARNING or compliance_failure == PLCY_WRT_WARNING):
            message = "Non Compliant Bucket Policy: %s. Review Policy: %s" % (bucket_name, bucket_policy)
            policy_notifier(bucket_name, subject, message)
        elif (compliance_failure == RD_COMBO_WARNING or compliance_failure == WRT_COMBO_WARNING):
            s3.put_bucket_acl(Bucket=bucket_name, ACL='private')
            message = "Public ACL & Non Compliant Bucket Policy: %s. Review Policy: %s" % (bucket_name, bucket_policy)
            policy_notifier(bucket_name, subject, message)
        logger.info(message)
    except KeyError as e:
        logger.info("Event already remediated.")
        return
    return  # done
