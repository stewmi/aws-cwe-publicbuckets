# Open Bucket Compliance Automation

## Overview
### Summary

This Lambda function will listen, using CloudWatch Events, to a Config rule that
is triggered to be non-compliant if a public-read or public-write policy is found.

Once a Non-Compliant Bucket is found,  it will add a private bucket acl to the bucket
and then message the bucket policy, if found, to an SNS topic that administrators
can subscribe to.

### Serverless Application Model
[Github Repository](https://github.com/awslabs/serverless-application-model)

[![SAM Webinar](https://img.youtube.com/vi/1k3XqBA2hYM/0.jpg)](http://www.youtube.com/watch?v=1k3XqBA2hYM)

AWS Serverless Application Model (AWS SAM) prescribes rules for expressing Serverless applications on AWS.

## Deployment

0. Pre Requisites:
  - Install Python

    `brew install python`

  - Install awscli

    `pip install awscli`

  - Configure Credentials

    `aws configure`

  - Create an S3 Bucket for deployments

    `bucket=$(aws s3 mb s3://your-awesome-deployment-bucket --output text | sed 's/make_bucket: //')`

1. Package the application

  `aws cloudformation package --template template.yml --s3-bucket $bucket --output-template-file packaged-template.yml`

2. Deploy the application

  `aws cloudformation deploy --template-file /path/to/packaged-template.yml --stack-name stop-the-data-leaks --capabilities CAPABILITY_IAM`


## Contributing

1. Create a Feature Branch
2. Make Improvements
3. Create Pull Request and notify current owner.
