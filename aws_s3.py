import boto
from boto.s3.key import Key
from boto.s3.deletemarker import DeleteMarker

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

def get_storage_location(main_root_url, local_location):
    return local_location.replace(main_root_url + "/", "")

def get_md5_hexdigest_of_file(location):
    return '"{}"'.format(hashlib.md5(open(location,'rb').read()).hexdigest())

def get_directories_from_path(path):
    return "/".join(path.split('/')[:-1])

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

def check_and_update_file(bucket, local_location, storage_location):
    k = bucket.get_key(storage_location)
    if k is None or (k and not k.etag == get_md5_hexdigest_of_file(local_location)):
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

def download_file(k, root_location):
    folder_path = "{}/{}".format(root_location, get_directories_from_path(k.name))
    if not os.path.exists(folder_path):
        os.makedirs(folder_path)
    download_start = time.time()
    logger.info('Starting to download {}'.format(k.name))
    try:
        k.get_contents_to_filename("{}/{}".format(root_location, k.name))
    except socket_error as serr:
        logger.error('Failed to download {}'.format(k.name))
    logger.info('Downloaded {} of size {} in {} seconds'.format(k.name, k.size, time.time() - download_start))

def sync_folder_to_bucket(bucket_name, root_folder):
    bucket = get_bucket(bucket_name)
    recursive_update(bucket, root_folder)
    soft_delete_non_existent_files(bucket, root_folder)

def sync_bucket_to_folder(bucket_name, root_folder):
    bucket = get_bucket(bucket_name)
    for k in bucket.get_all_keys():
        local_location = "{}/{}".format(root_folder, k.name)
        if not os.path.isfile(local_location) or not k.etag == get_md5_hexdigest_of_file(local_location):
            download_file(k, root_folder)

def delete_file_from_bucket(bucket_name, file_path):
    bucket = get_bucket(bucket_name)
    k = bucket.get_key(file_path)
    if k:
        bucket.delete_key(file_path)
        logger.info('Deleted file {}'.format(k.name))
    else:
        logger.error('File {} not found on bucket to be deleted'.format(k.name))

def restore_file_from_bucket(bucket_name, file_path):
    bucket = get_bucket(bucket_name)
    versions = filter(lambda v: isinstance(v, DeleteMarker) and v.is_latest, bucket.get_all_versions(prefix=file_path))
    if versions:
        for v in versions:
            bucket.delete_key(v.name, version_id=v.version_id)
        logger.info('File {} restored in bucket'.format(v.name))
    else:
        logger.error('File {} not found or may already exist in bucket therefore cannot be restored'.format(file_path))

def run_function(option, opt_str, value, parser):
    global logger
    logger= logging.getLogger('s3.{}'.format(option.dest))
    start_time = time.time()
    globals()[option.dest](*value)
    logger.info('{} with args {} finished in {}'.format(option.dest, ', '.join(value), time.time() - start_time))

if __name__ == "__main__":
    parser = OptionParser()
    parser.add_option(
        '-f',
        dest="sync_folder_to_bucket",
        nargs=2,
        metavar='<bucket name> <root folder>',
        help="Sync folder with bucket in AWS",
        callback= run_function,
        action='callback',
        type='str'
    )
    parser.add_option(
        '-b',
        dest="sync_bucket_to_folder",
        nargs=2,
        metavar='<bucket name> <root folder>',
        help="Sync bucket in AWS with folder",
        callback= run_function,
        action='callback',
        type='str'
    )
    parser.add_option(
        '-d',
        dest="delete_file_from_bucket",
        nargs=2,
        metavar='<bucket name> <file path>',
        help="Delete a file in a bucket",
        callback= run_function,
        action='callback',
        type='str'
    )
    parser.add_option(
        '-r',
        dest="restore_file_from_bucket",
        nargs=2,
        metavar='<bucket name> <file path>',
        help="Restore latest version of file in a bucket",
        callback= run_function,
        action='callback',
        type='str'
    )
    (options, args) = parser.parse_args()
