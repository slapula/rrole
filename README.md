# Rust Role (RRole)

`rrole` exists as both my introduction to the Rust programming language and a tool for me to manage AWS cross account role assumption.  There are several main actions this tool can perform.

```bash
USAGE:
    rrole <action> --source <source_acct> --destination <destination_acct> --user <user> --role <role>
```

## Actions

`status`: This action describes your current credentials and, if assumed into a role, the time remaining in the session.

```bash
$ rrole status
account: 123456789012
arn: arn:aws:iam::123456789012:user/test_user
access_id: ABCDEFG1HIJKLMNOP2QRS
```

`assume`: This action makes a call to AWS to assume a specific cross account role.  A successful call will set the appropriate environment variables with the values returned by the call.  The variables in question are `AWS_ACCESS_KEY_ID`, `AWS_SECRET_ACCESS_KEY`, and `AWS_SESSION_TOKEN`.  This tool also populates an additional variable for use with the `status` action and it is called `AWS_SESSION_EXPIRES`.  It exists to allow the `status` action to determinte the time left in your session.

The `assume` action requires the following flags:

* `-s` or `--source`: The source AWS account you will be assuming from.
* `-d` or `--destination`: The destination AWS account where the role you want to assume resides.
* `-u` or `--user`:  Your IAM user name.
* `-r` or `--role`: The IAM cross account role you would like to assume.
* `-m` or `--mfa`: Enables MFA for this session if required. As a result, this flag is optional.

```bash
$ rrole assume -u test_user -s 123456789012 -d 98765432109 -r hot_cross_role --mfa
Please enter MFA token:
123456
$
```

`reset`: This action unsets the AWS related environment variables related to the temporary credentials generated by this tool.  If you do not have the credentials stored elsewhere then you will likely need re-assume the role.

```bash
$ rrole reset
Resetting assumed role variables...
$
```