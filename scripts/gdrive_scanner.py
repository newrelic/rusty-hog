# A python script to "scan" a GDrive folder containing docs and binaries.
# You will need the Google Python API libraries:
#   pip install --upgrade google-api-python-client google-auth-httplib2 google-auth-oauthlib

from __future__ import print_function

import csv
import io
import json
import os.path
import random
import subprocess
import sys
import tempfile
import uuid
from multiprocessing import Pool
from tempfile import tempdir

from googleapiclient.discovery import build
from google_auth_oauthlib.flow import InstalledAppFlow
from google.auth.transport.requests import Request
from google.oauth2.credentials import Credentials
import argparse

from googleapiclient.http import MediaIoBaseDownload

INSIGHTS_INSERT_KEY = os.environ["INSIGHTS_INSERT_KEY"]
INSIGHTS_ACCT_ID = os.environ["INSIGHTS_ACCT_ID"]
DUROC_HOG_PATH = os.environ["DUROC_HOG_PATH"]
ANKAMALI_HOG_PATH = os.environ["ANKAMALI_HOG_PATH"]

# If modifying these scopes, delete the file token.json.
SCOPES = ['https://www.googleapis.com/auth/drive.readonly']
tempdir = tempfile.gettempdir()
creds = None
# The file token.json stores the user's access and refresh tokens, and is
# created automatically when the authorization flow completes for the first
# time.
if os.path.exists('temptoken_scanner.json'):
    creds = Credentials.from_authorized_user_file('temptoken_scanner.json', SCOPES)
# If there are no (valid) credentials available, let the user log in.
if not creds or not creds.valid:
    if creds and creds.expired and creds.refresh_token:
        creds.refresh(Request())
    else:
        flow = InstalledAppFlow.from_client_secrets_file(
            'clientsecret.json', SCOPES)
        creds = flow.run_local_server(port=0)
    # Save the credentials for the next run
    with open('temptoken_scanner.json', 'w') as token:
        token.write(creds.to_json())

SERVICE = build('drive', 'v3', credentials=creds)


def scan_ankamali(x):
    filename = os.path.join(tempdir, str(uuid.uuid4()))
    print(f"Fetching {x['id']}")
    s = subprocess.run([ANKAMALI_HOG_PATH, "--outputfile", filename, x['id']],
                       capture_output=True)
    return {"id": x['id'], "results": filename}

def scan_duroc(x):
    results_filename = os.path.join(tempdir, str(uuid.uuid4()))
    scan_target_filename = os.path.join(tempdir, x['name'])

    print(f"Fetching {x['id']} {x['webContentLink']} {x['name']} and writing to {scan_target_filename}")
    request = SERVICE.files().get_media(fileId=x['id'])
    fh = io.BytesIO()
    downloader = MediaIoBaseDownload(fh, request)
    done = False
    while done is False:
        status, done = downloader.next_chunk()
    with open(scan_target_filename, 'wb') as f:
        f.write(fh.getbuffer())
        f.close()
    s = subprocess.run([DUROC_HOG_PATH, "-z", scan_target_filename],
                       capture_output=True)
    print(s.stdout)
    print(s.stderr)
    # os.remove(scan_target_filename)
    return {"id": x['id'], "results": results_filename, "name": x['name'], "link": x['webContentLink']}

def parseargs():
    parser = argparse.ArgumentParser()
    parser.add_argument("--driveid", help="GDrive id of drive to scan, defaults to user's drive")
    parser.add_argument("-f", "--folder", help="Scan within specific folder ID")
    parser.add_argument("-r", "--recursive", help="Scan files with parents")
    parser.add_argument("--sample", help="Only scan a sample of available files", type=int)
    parser.add_argument("--modifiedTime", help="Only scan files after a specific date (ISO format)", type=int)
    parser.add_argument("--scope", help="GDrive scoping option", choices=['user', 'drive', 'domain'], default='user')
    return parser.parse_args()

def main(args):
    """Shows basic usage of the Drive v3 API.
    Prints the names and ids of the first 10 files the user has access to.
    """

    # Call the Drive v3 API
    file_get_kwargs = {
        'pageSize': 100,
        'fields': 'nextPageToken, files(contentHints/thumbnail,fileExtension,iconLink,id,name,size,thumbnailLink,webContentLink,webViewLink,mimeType,parents)',
        'corpora': args.scope
    }
    if args.driveid:
        file_get_kwargs['driveId'] = args.driveid
    if args.folder:
        file_get_kwargs['q'] = f"'{args.folder}' in parents"
    page = 1
    print(f"Fetching page {page}")
    results = SERVICE.files().list(**file_get_kwargs).execute()
    page += 1
    files = results.get('files', [])
    nextPageToken = results.get('nextPageToken', None)
    while nextPageToken:
        file_get_kwargs['pageToken'] = nextPageToken
        print(f"Fetching page {page}")
        results = SERVICE.files().list(**file_get_kwargs).execute()
        page += 1
        files += results.get('files', [])
        nextPageToken = results.get('nextPageToken', None)
    print("Completed fetching file-listing")
    files = list(filter(lambda x: x['mimeType'] != 'application/vnd.google-apps.folder', files))
    ankamali_hog_files = list(filter(lambda x: x['mimeType'] == 'application/vnd.google-apps.spreadsheet' or x['mimeType'] == 'application/vnd.google-apps.document', files))
    mime_block_list = [
        'application/vnd.google-apps.audio',
        'application/vnd.google-apps.document',
        'application/vnd.google-apps.drive',
        'application/vnd.google-apps.drawing',
        'application/vnd.google-apps.file',
        'application/vnd.google-apps.folder',
        'application/vnd.google-apps.form',
        'application/vnd.google-apps.fusiontable',
        'application/vnd.google-apps.map',
        'application/vnd.google-apps.photo',
        'application/vnd.google-apps.presentation',
        'application/vnd.google-apps.script',
        'application/vnd.google-apps.shortcut',
        'application/vnd.google-apps.site',
        'application/vnd.google-apps.spreadsheet',
        'application/vnd.google-apps.unknown',
        'application/vnd.google-apps.video'
    ]
    duroc_hog_files = list(filter(lambda x: x['mimeType'] not in mime_block_list, files))
    if args.sample:
        if len(ankamali_hog_files) > args.sample:
            ankamali_hog_files = random.sample(ankamali_hog_files, args.sample)
        if len(duroc_hog_files) > args.sample:
            duroc_hog_files = random.sample(duroc_hog_files, args.sample)

    output_ankamali = []
    output_duroc = []

    print("Starting the Rusty Hog scanning process...")

    if len(ankamali_hog_files) > 0:
        with Pool(4) as p:
            output_ankamali.extend(p.map(scan_ankamali, ankamali_hog_files))

    if len(duroc_hog_files) > 0:
        with Pool(4) as p:
            output_duroc.extend(p.map(scan_duroc, duroc_hog_files))

    print("Complete! Dumping output to output_duroc.csv...")

    with open('output_duroc.csv', 'w') as csvfile:
        writer = csv.writer(csvfile)
        writer.writerow(['id', 'reason', 'stringsFound', 'path', 'linenum', 'weblink'])
        for result in output_duroc:
            try:
                print(f"Reading duroc hog results {result['results']}")
                with open(result['results'], 'r') as f:
                    result_list = json.load(f)
                    for finding in result_list:
                        writer.writerow([result['id'],
                                         finding['reason'],
                                         str(finding['stringsFound']),
                                         result['name'],
                                         finding['linenum'],
                                         result['link']])
            except:
                print("Unexpected error:", sys.exc_info()[0])
            try:
                os.remove(result['results'])
            except:
                print("Unexpected error:", sys.exc_info()[0])

    print("Complete! Dumping output to output_ankamali.csv...")

    with open('output_ankamali.csv', 'w') as csvfile:
        writer = csv.writer(csvfile)
        writer.writerow(['id', 'reason', 'stringsFound', 'path', 'date'])
        for result in output_ankamali:
            try:
                with open(result['results'], 'r') as f:
                    result_list = json.load(f)
                    for finding in result_list:
                        writer.writerow([result['id'],
                                         finding['reason'],
                                         str(finding['stringsFound']),
                                         finding['path'],
                                         finding['date']])
            except:
                print(f"Couldn't find duroc hog output {result['results']}")
            try:
                os.remove(result['results'])
            except:
                pass



if __name__ == '__main__':
    args = parseargs()
    main(args)