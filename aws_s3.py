import boto
from boto.s3.key import Key

import os
import time
import hashlib
import logging
from socket import error as socket_error
from optparse import OptionParser

logging.basicConfig(
    filename='aws_log',
    filemode='a',
    format='[%(asctime)s] %(name)s %(levelname)s %(message)s',
    datefmt='%Y-%m-%d %H:%M:%S',
    level=logging.INFO
)
logger = logging.getLogger('s3')

def get_s3_connection():
    conn = boto.connect_s3()
    logger.info('Connection to s3 estabilished')
    return conn

def get_bucket(bucket_name):
    conn = get_s3_connection()
    bucket = conn.get_bucket(bucket_name)
    bucket_location = bucket.get_location()
    if bucket_location:
        conn = boto.s3.connect_to_region(bucket_location)
        bucket = conn.get_bucket(bucket_name)
    logger.info('Connected to bucket {} in {}'.format(bucket_name, bucket_location))
    return bucket

def upload_file(bucket, local_location, storage_location):
    k = Key(bucket)
    k.key = storage_location
    upload_start = time.time()
    logger.info('Starting to upload {}'.format(local_location))
    try:
        k.set_contents_from_filename(local_location)
    except socket_error as serr:
        logger.error('Failed to upload {}'.format(local_location))
    logger.info('Uploaded {} of size {} in {} seconds'.format(storage_location, os.path.getsize(local_location), time.time() - upload_start))

def get_storage_location(main_root_url, local_location):
    return local_location.replace(main_root_url + "/", "")

def check_and_update_file(bucket, local_location, storage_location):
    k = bucket.get_key(storage_location)
    if k is None or (k and not k.etag == '"{}"'.format(hashlib.md5(open(local_location,'rb').read()).hexdigest())):
        upload_file(bucket, local_location, storage_location)

def recursive_update(bucket, main_root_url, current_url=None):
    for f in os.listdir(current_url or main_root_url):
        local_location = "{}/{}".format(current_url or main_root_url, f)
        if os.path.isfile(local_location):
            check_and_update_file(
                bucket,
                local_location,
                get_storage_location(main_root_url, local_location)
            )
        elif os.path.isdir(local_location):
            recursive_update(bucket, main_root_url, local_location)

def soft_delete_non_existent_files(bucket, root_folder):
    for k in bucket.get_all_keys():
        if not os.path.isfile("{}/{}".format(root_folder, k.name)):
            k.delete()
            logger.info('Deleted file {}'.format(k.name))

def sync_bucket_to_folder(bucket_name, root_folder):
    sync_bucket_to_folder_start = time.time()
    bucket = get_bucket(bucket_name)
    wsd = [v for v in bucket.list_versions()]
    recursive_update(bucket, root_folder)
    soft_delete_non_existent_files(bucket, root_folder)
    logger.info('Updating bucket {} finished in {}'.format(bucket_name, time.time() - sync_bucket_to_folder_start))

def run_function(option, opt_str, value, parser):
    globals()[option.dest](*value)

if __name__ == "__main__":
    parser = OptionParser()
    parser.add_option(
        '-s',
        dest="sync_bucket_to_folder",
        nargs=2,
        metavar='<bucket name> <root folder>',
        help="Sync folder with bucket in AWS",
        callback= run_function,
        action='callback',
        type='str'
    )
    (options, args) = parser.parse_args()
