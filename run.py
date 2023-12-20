#!/usr/bin/env python3

"""
author: Imam Omar Mochtar (iomarmochtar@gmail.com)
"""

import sys
import os
import argparse
import urllib3
import logging as log
import re
import subprocess
import datetime
import requests
from typing import List, Tuple, Union, Dict
from requests.auth import HTTPBasicAuth

ZMMAILBOX_PATH = "/opt/zimbra/bin/zmmailbox"
DEFAULT_DELIMITER = ";"
MAILBOX_DOWNLOAD_FORMAT = "tgz"
MESSAGE_SEARCH_DATETIME_FORMAT = "%m/%d/%y"

log.basicConfig(format='%(asctime)s - %(levelname)s - %(message)s', datefmt='%d-%b-%y %H:%M:%S', level=log.INFO)
urllib3.disable_warnings()
message_search_re = re.compile(r"(\d+/\d+/\d+)\s+\d+:\d+$")

class ValidationErr(Exception):
    pass

def run_shell(command: str, check_err: bool = True) -> subprocess.CompletedProcess:
    """
    wrapper of shell command execution
    """
    log.debug(f"running shell command ~> {command}")
    call_cmd = subprocess.run(command, shell=True, capture_output=True, text=True)
    if check_err and call_cmd.returncode != 0:
        raise subprocess.CalledProcessError(
            cmd=f"error in executing command: {command}, output: {call_cmd.stderr}",
            returncode=call_cmd.returncode,
        )
    return call_cmd


def read_account_list(path: str, delimiter: str=DEFAULT_DELIMITER) -> List[Tuple[str, str]]:
    line_count = 0
    result = []
    with open(path, "r") as fh:
        for line in fh.readlines():
            line_count += 1
            line = line.strip()
            # if commented
            if not line or line.startswith("#"):
                continue
            source_account, dest_account = (line, line)
            brk = line.split(delimiter)
            # for different destination
            if len(brk) == 2:
                source_account, dest_account = brk
            elif len(brk) > 2:
                raise ValidationErr(f"invalid format in account list file at line {line_count} ({line}), ensure to use format [SOURCE_ACC];[DEST_ACC] or [SOURCE_AND_DEST_ACC]")
            result.append((source_account, dest_account))
    return result

def get_last_email_date(account: str) -> Union[datetime.datetime, None]:
    cmd = f'{ZMMAILBOX_PATH} -z -m {account} s --types message -l 1 -s dateDesc "is:anywhere"'
    result = run_shell(cmd)
    for line in result.stdout.split("\n"):
        message_search_found = message_search_re.search(line)
        if not message_search_found:
            continue
        return datetime.datetime.strptime(message_search_found.group(1), MESSAGE_SEARCH_DATETIME_FORMAT)
    return None

def download_mailbox_data(zimbra_source: str, account: str, query: Dict[str, str], auth: Tuple[str, str], dest_path: str, chunk_size: int=8192) -> None:
    basic_auth = HTTPBasicAuth(auth[0], auth[1]) 
    url = f"{zimbra_source}/service/home/{account}"
    log.info(f"downloading mailbox data ~> {url}")
    with requests.get(url, auth=basic_auth, params=query, stream=True, verify=False) as r:
        r.raise_for_status()
        with open(dest_path, "wb") as f:
            for chunk in r.iter_content(chunk_size=chunk_size): 
                f.write(chunk)

def upload_mailbox_data(mailbox_dump_path: str, target_account: str) -> None:
    log.warning(f"upload mailbox data {mailbox_dump_path} to target account {target_account}")
    cmd = f'{ZMMAILBOX_PATH} -z -m {target_account} postRestURL "//?fmt={MAILBOX_DOWNLOAD_FORMAT}&resolve=skip" {mailbox_dump_path}'
    run_shell(cmd)
    log.info(f"successfully restore mailbox data ({mailbox_dump_path}) for account {target_account}")

def main(args: argparse.Namespace) -> None: 
    download_dir = args.download_dir
    zimbra_source = args.zimbra_source
    admin_user = args.admin_user
    admin_password = args.admin_password
    use_existing_data = args.use_existing_data
    
    if args.debug:
        log.getLogger().setLevel(log.DEBUG)

    if not os.path.isdir(download_dir):
        raise ValidationErr(f"download directory is not exists ({download_dir})")

    account_list_path = args.account_list
    if not os.path.isfile(account_list_path):
        raise ValidationErr(f"account list reference file is not found ({account_list})")

    start_time = datetime.datetime.now()
    for source_acc, dest_acc in read_account_list(account_list_path):
        log.info(f"processing {source_acc} ~> {dest_acc}")
        last_email_date = get_last_email_date(dest_acc)
        download_mbx_params = {"fmt": MAILBOX_DOWNLOAD_FORMAT}
        # fetch all of email in source account since the last email found in destination account, take back one day for more sure
        if last_email_date != None:
            log.info(f"detected the last email date in destination account ({dest_acc}) is {last_email_date}, decreasing to one day as reference to download mailbox content")
            download_since = last_email_date - datetime.timedelta(days=1)
            download_mbx_params["query"] = f"after:{download_since.strftime(MESSAGE_SEARCH_DATETIME_FORMAT)}"
        else:
            log.warning(f"no email message found in destination account {dest_acc}, will capture all of email in {source_acc}")
        mailbox_dump_path = os.path.join(download_dir, f"{source_acc}.{MAILBOX_DOWNLOAD_FORMAT}")
        if os.path.isfile(mailbox_dump_path) and use_existing_data:
            log.info(f"use existing data flag is set and source data is exist ({mailbox_dump_path}), will using it ...")
        else:
            log.info(f"downloading email content in {source_acc} since using query `{download_mbx_params}` to destination {mailbox_dump_path}")
            download_mailbox_data(zimbra_source, account=source_acc, auth=(admin_user, admin_password), query=download_mbx_params, dest_path=mailbox_dump_path)

        upload_mailbox_data(mailbox_dump_path, dest_acc)

    elapsed_time = datetime.datetime.now() - start_time
    log.info(f"done, elapsed time: {elapsed_time}")

if __name__ == "__main__":
    ap = argparse.ArgumentParser(
        description="script in automating dump and restore mailbox based on last email on mailbox"
    )
    ap.add_argument("-d", "--download-dir", help="directory that used in storing mailbox file", required=True)
    ap.add_argument("-l", "--account_list", help="account list file", required=True)
    ap.add_argument("-s", "--zimbra-source", help="source of zimbra instance with format https://[HOST]:[PORT]", required=True)
    ap.add_argument("-a", "--admin-user", help="global admin account in zimbra source", required=True)
    ap.add_argument("-p", "--admin-password", help="global admin password in zimbra source", required=True)
    ap.add_argument("-u", "--use-existing-data", help="if existing data path is exist then use it instead redownload", action="store_true", default=False)
    ap.add_argument("-x", "--debug", help="enable debug mode", action="store_true", default=False)
    main(ap.parse_args())
