# guardduty-stix
A program to turn GuardDuty findings from the AWS API into compliant STIX 2.0

This is a C# .NET Core program that will connect to your AWS GuardDuty instance
and retrieve the first 50 findings and return them as STIX-formatted results in
a single bundle.

This was a proof-of-concept to introduce myself to STIX.  Depending on the
interest in this tool, I may add more bells and whistles to this if you find
it useful.  Issues, comments, and pull requests are welcome.

## Usage:
```
guardduty-stix --profile=default --region=us-east-1
```

Output is JSON in STIX 2.0 format so it can be piped directly into other tools.
Errors are provided on stderr, and there are no verbosity options.  If you do
not have an AWS profile file setup, you can provide AWS access key credentials
manually, like:

```
guardduty-stix --key=AAAXACCESSKEYID --secret=AAAASUPERSECRET --region=whatever
```
