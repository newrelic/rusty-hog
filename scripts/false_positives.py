#!/usr/bin/env python
import csv

fpwords = ['foo',
           'bar',
           'example',
           'test',
           'host.com',
           'LicenseEditMaskedEdit',
           'user:pass',
           'git@github',
           'TRAFFIC_INSIGHTS',
           'GithubComGoogleSubcommands',
           'DO_NOT_USE',
           'account', # FILTERS ALL ACCOUNT ID FINDINGS!
           'DO_NOT_PASS_THIS',
           '0000000000',
           'local_development',
           'bootstrap',
           'local_production',
           'username@hostname',
           '1234567890',
           'metadata-injection',
           'kubernetes-static',
           'fitzgen@github.com',
           'user@domain.com',
           'admin:admin123',
           '$gh_token:x-oauth-basic',
           'templates',
           'you-must-create',
           'username:password',
           'Agent.Core.dll',
           'code.highcharts.com',
           'OS_DEPENDENT_NETWORK',
           'LicenseKeyEditEdit',
           '@bitbucket.org/',
           '123456789',
           'abcdefghij',
           'XXXXXXXXXX',
           'YOUR_GITLAB_TOKEN',
           'rpm_site_local_dev__secret',
           'secret-key-authenticated-encryption-secretbox'
           ]


def fpfilter(x):
    for (k,v) in x.items():
        for badword in fpwords:
            if badword.lower() in v.lower():
                return False
    return True


with open('output.csv') as f:
    reader = csv.DictReader(f)
    out = filter(fpfilter, reader)
    with open('output_filtered.csv', 'w') as o:
        writer = csv.DictWriter(o, fieldnames=['Repository','reason','stringsFound','path','commit','commitHash','date'])
        writer.writerows(out)
