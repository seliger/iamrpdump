iamrpdump
=========

Simple export and import script for Amazon IAM using boto3 to work.


Usage
-----
```
usage: iamrpdump.py [-h] [-m MODE] [-p PROFILE] [--log LOG]

Simple IAM role policy export/import utility.

optional arguments:
  -h, --help            show this help message and exit
  -m MODE, --mode MODE  'export' or 'import'
  -p PROFILE, --profile PROFILE
                        AWS profile name to use. Allows to you to choose
                        alternate profile from your AWS credentials file.
  --log LOG             Logging level - DEBUG|INFO|WARNING|ERROR|CRITICAL
                        [optional]

IAM files are stored in a 'dump' subdirectory, and are restored from there as well by default.
```

AWS example
-----------
The following examples assume your AWS access key and secret key is present in ~/.aws/credentials. This assumes the credential file has configuration stanzas called "account_a" and "account_b".

Export from Account A and Import into Account B
```
python iamrpdump.py -m export -p account_a

python iamrpdump.py -m import -p account_b

```
