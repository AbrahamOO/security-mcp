import * as cdk from "aws-cdk-lib";
import { Bucket } from "aws-cdk-lib/aws-s3";
import { PolicyStatement } from "aws-cdk-lib/aws-iam";

export class InsecureStack extends cdk.Stack {
  build() {
    const bucket = new Bucket(this, "Data", {
      removalPolicy: cdk.RemovalPolicy.DESTROY,
    });

    bucket.grantReadWrite(this.role);

    this.role.addToRolePolicy(
      new PolicyStatement({
        actions: ["*"],
        resources: ["*"],
      })
    );

    const table = new cdk.aws_dynamodb.Table(this, "T", {
      removalPolicy: RemovalPolicy.DESTROY,
    });
    return table;
  }
}
