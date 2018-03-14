vibe-aws [![Build Status](https://travis-ci.org/vibe-aws/vibe-aws.svg?branch=master)](https://travis-ci.org/vibe-aws/vibe-aws)
========

An AWS client library for the D programming language, based on the vibe.d
framework.

Supported Services
------------------

I'm implementing this along with another project, as far as I need it, so it
may not have all of AWS's features, but it's a start. For one thing, you won't
need to implement the AWS request signing again if you take this code :).

Right now, the services supported are:

* DynamoDB

DynamoDB
--------

Only simple puts and gets are supported yet:

```d
    import std.stdio;
    import vibe.aws.dynamodb;

    auto creds = new StaticAWSCredentials("keyId", "secretKey");
    auto ddb = new DynamoDB("us-east-1", creds);
    auto table = ddb.table("mytable");

    auto item1 = Item().set("key", "value");
    ddb.put(item1);

    auto item2 = ddb.get("key", "value");
    writeln(item2["key"]);
```
