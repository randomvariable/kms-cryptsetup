kms-cryptsetup
==============

Let's you encrypt on-premise disks and securely store the keys in DynamoDB
using KMS.

Design
------
`kms-cryptsetup` can be used on stateless systems like CoreOS or Intel Clear
Linux.

It uses SMBIOS IDs and disk serial numbers to uniquely identify computers
and disks and retrieve encryption keys from DynamoDB, which are in turn
encrypted using the AWS Key Management Service.

Each computer has an IAM user account with fine grained access control to
their key prefix in DynamoDB.

You also provide individual grants to each computer to decrypt records in
DynamoDB. These can be revoked and reinstated at any time, and provide an
alternative to using hardware devices like TPMs or Yubikeys which could
potentially be physically stolen together with the hard disk.


Setup
---

```
AWS_REGION=<region> ./kms-cryptsetup # lists available commands
```

## Create the DynamoDB table

`kms-cryptsetup` uses a DynamoDB table called `kms-cryptsetup` to store keys.
Create this using:

```
AWS_REGION=<region> ./kms-cryptsetup create-table
```

## Grant the computer access
Install/copy `kms-cryptsetup` to the target computer and run:

```
AWS_REGION=<region> ./kms-cryptsetup computer-context
```

which should print something like:
```
supermicrozaaaaaaaa000000000000000000000aaaaaaaaaa
```

This is determined from the following DMI values:
* The motherboard vendor
* The motherboard serial number
* The motherboard product UUID

If these keys are not available, you can specify these manually in the next steps.

On your workstation, given some AWS credentials, run:

```
AWS_REGION=<region> ./kms-cryptsetup grant-computer -c <computer context from above>
```

If this is a new IAM user, the tool will print the AWS Access Key and Secret Access Key
to be installed to `/root/.aws/credentials` or used as environment variables on the target
system.

## Encrypt a disk

`kms-cryptsetup` can pass the relevant parameters to `cryptsetup` with the following defaults:

```
cryptsetup --allow-discards --cipher aes-xts-plain64 --key-file - --key-size 256 open --type plain /dev/<target device> /dev/mapper/dmcrypt-<device>
```

To do this, run:
```
AWS_REGION=<region> ./kms-cryptsetup encrypt-disk -d <device>
```

## Run a custom command
To use your own cryptsetup command line, use the following

```
AWS_REGION=<region> ./kms-cryptsetup output-key -d <device> | crypsetup <options>
```

## Revoke a computer's access

This will revoke a computer's access. This can be restored at any time using
`grant-computer`. Access Keys do not need to be rotated for this to work.

```
AWS_REGION=<region> ./kms-cryptsetup revoke-computer -c <computer context>
```
