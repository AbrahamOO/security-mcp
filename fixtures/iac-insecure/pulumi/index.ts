import * as aws from "@pulumi/aws";

const provider = new aws.Provider("custom", {
  region: "us-east-1",
  accessKey: "AKIAIOSFODNN7EXAMPLE",
  secretKey: "wJalrXUtnFEMIabcdEFGHIK7MDENGbPxRfiCYEXA",
});

export const out = provider.id;
