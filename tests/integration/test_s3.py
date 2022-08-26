# TODO: migrate tests to tests/integration/s3/
#  DO NOT ADD ADDITIONAL TESTS HERE. USE PYTEST AND RUN TESTS AGAINST AWS!
import base64
import gzip
import hashlib
import json
import os
import shutil
import time
import unittest
from io import BytesIO
from unittest.mock import patch
from urllib.parse import parse_qs, quote, urlparse
from urllib.request import Request

import boto3
import pytest
import requests
from botocore.client import Config
from botocore.exceptions import ClientError

from localstack import config, constants
from localstack.constants import (
    AWS_REGION_US_EAST_1,
    S3_VIRTUAL_HOSTNAME,
    TEST_AWS_ACCESS_KEY_ID,
    TEST_AWS_SECRET_ACCESS_KEY,
)
from localstack.services.awslambda.lambda_api import use_docker
from localstack.services.awslambda.lambda_utils import LAMBDA_RUNTIME_NODEJS14X
from localstack.services.s3 import s3_utils
from localstack.utils import testutil
from localstack.utils.aws import aws_stack
from localstack.utils.common import (
    get_service_protocol,
    new_tmp_dir,
    run,
    safe_requests,
    short_uid,
    to_bytes,
    to_str,
)

TEST_BUCKET_NAME_WITH_POLICY = "test-bucket-policy-1"
TEST_BUCKET_WITH_VERSIONING = "test-bucket-versioning-1"

TEST_BUCKET_NAME_2 = "test-bucket-2"
TEST_KEY_2 = "test-key-2"
TEST_GET_OBJECT_RANGE = 17

TEST_REGION_1 = "eu-west-1"

THIS_FOLDER = os.path.dirname(os.path.realpath(__file__))
TEST_LAMBDA_PYTHON_DOWNLOAD_FROM_S3 = os.path.join(
    THIS_FOLDER, "awslambda", "functions", "lambda_triggered_by_sqs_download_s3_file.py"
)

BATCH_DELETE_BODY = """
<Delete xmlns="http://s3.amazonaws.com/doc/2006-03-01/">
  <Object>
    <Key>%s</Key>
  </Object>
  <Object>
    <Key>%s</Key>
  </Object>
</Delete>
"""


class PutRequest(Request):
    """Class to handle putting with urllib"""

    def __init__(self, *args, **kwargs):
        Request.__init__(self, *args, **kwargs)

    def get_method(self, *args, **kwargs):
        return "PUT"


# def test_host_and_path_addressing(wrapped):
#     """ Decorator that runs a test method with both - path and host style addressing. """
#     # TODO - needs to be fixed below!
#     def wrapper(self):
#         try:
#             # test via path based addressing
#             TestS3.OVERWRITTEN_CLIENT = aws_stack.create_external_boto_client('s3', config={'addressing_style': 'virtual'})
#             wrapped()
#             # test via host based addressing
#             TestS3.OVERWRITTEN_CLIENT = aws_stack.create_external_boto_client('s3', config={'addressing_style': 'path'})
#             wrapped()
#         finally:
#             # reset client
#             TestS3.OVERWRITTEN_CLIENT = None
#     return


class TestS3(unittest.TestCase):
    OVERWRITTEN_CLIENT = None

    def setUp(self):
        # Default S3 operations should be happening in us-east-1, hence passing in the region
        # here (otherwise create_bucket(..) would fail without specifying a location constraint.
        # Dedicated multi-region tests use specific clients further below.
        self._s3_client = aws_stack.create_external_boto_client(
            "s3", region_name=AWS_REGION_US_EAST_1
        )
        self.sqs_client = aws_stack.create_external_boto_client("sqs")

    @property
    def s3_client(self):
        return TestS3.OVERWRITTEN_CLIENT or self._s3_client

    def test_multipart_copy_object_etag(self):
        bucket_name = "test-bucket-%s" % short_uid()
        key = "test.file"
        copy_key = "copy.file"
        src_object_path = "%s/%s" % (bucket_name, key)
        content = "test content 123"

        self.s3_client.create_bucket(Bucket=bucket_name)
        multipart_etag = self._perform_multipart_upload(bucket=bucket_name, key=key, data=content)[
            "ETag"
        ]
        copy_etag = self.s3_client.copy_object(
            Bucket=bucket_name, CopySource=src_object_path, Key=copy_key
        )["CopyObjectResult"]["ETag"]
        # etags should be different
        self.assertNotEqual(multipart_etag, copy_etag)

        # cleanup
        self.s3_client.delete_objects(
            Bucket=bucket_name, Delete={"Objects": [{"Key": key}, {"Key": copy_key}]}
        )
        self.s3_client.delete_bucket(Bucket=bucket_name)

    def test_set_external_hostname(self):
        bucket_name = "test-bucket-%s" % short_uid()
        key = "test.file"
        hostname_before = config.HOSTNAME_EXTERNAL
        config.HOSTNAME_EXTERNAL = "foobar"
        try:
            content = "test content 123"
            acl = "public-read"
            self.s3_client.create_bucket(Bucket=bucket_name)
            # upload file
            response = self._perform_multipart_upload(
                bucket=bucket_name, key=key, data=content, acl=acl
            )
            expected_url = "%s://%s:%s/%s/%s" % (
                get_service_protocol(),
                config.HOSTNAME_EXTERNAL,
                config.service_port("s3"),
                bucket_name,
                key,
            )
            self.assertEqual(expected_url, response["Location"])
            # fix object ACL - currently not directly support for multipart uploads
            self.s3_client.put_object_acl(Bucket=bucket_name, Key=key, ACL=acl)
            # download object via API
            downloaded_object = self.s3_client.get_object(Bucket=bucket_name, Key=key)
            self.assertEqual(content, to_str(downloaded_object["Body"].read()))
            # download object directly from download link
            download_url = response["Location"].replace(
                "%s:" % config.HOSTNAME_EXTERNAL, "localhost:"
            )
            response = safe_requests.get(download_url)
            self.assertEqual(200, response.status_code)
            self.assertEqual(content, to_str(response.content))
        finally:
            config.HOSTNAME_EXTERNAL = hostname_before

    def test_s3_static_website_hosting(self):

        bucket_name = "test-%s" % short_uid()

        self.s3_client.create_bucket(Bucket=bucket_name)
        index_obj = self.s3_client.put_object(
            Bucket=bucket_name, Key="test/index.html", Body="index", ContentType="text/html"
        )
        error_obj = self.s3_client.put_object(
            Bucket=bucket_name, Key="test/error.html", Body="error", ContentType="text/html"
        )
        actual_key_obj = self.s3_client.put_object(
            Bucket=bucket_name, Key="actual/key.html", Body="key", ContentType="text/html"
        )
        with_content_type_obj = self.s3_client.put_object(
            Bucket=bucket_name,
            Key="with-content-type/key.js",
            Body="some js",
            ContentType="application/javascript; charset=utf-8",
        )
        self.s3_client.put_object(
            Bucket=bucket_name,
            Key="to-be-redirected.html",
            WebsiteRedirectLocation="actual/key.html",
        )
        self.s3_client.put_bucket_website(
            Bucket=bucket_name,
            WebsiteConfiguration={
                "IndexDocument": {"Suffix": "index.html"},
                "ErrorDocument": {"Key": "test/error.html"},
            },
        )

        headers = aws_stack.mock_aws_request_headers("s3")
        headers["Host"] = s3_utils.get_bucket_website_hostname(bucket_name)

        # actual key
        url = "https://{}.{}:{}/actual/key.html".format(
            bucket_name, constants.S3_STATIC_WEBSITE_HOSTNAME, config.EDGE_PORT
        )
        response = requests.get(url, headers=headers, verify=False)
        self.assertEqual(200, response.status_code)
        self.assertEqual("key", response.text)
        self.assertIn("content-type", response.headers)
        self.assertEqual("text/html", response.headers["content-type"])
        self.assertIn("etag", response.headers)
        self.assertEqual(actual_key_obj["ETag"], response.headers["etag"])

        # If-None-Match and Etag
        response = requests.get(
            url, headers={**headers, "If-None-Match": actual_key_obj["ETag"]}, verify=False
        )
        self.assertEqual(304, response.status_code)

        # key with specified content-type
        url = "https://{}.{}:{}/with-content-type/key.js".format(
            bucket_name, constants.S3_STATIC_WEBSITE_HOSTNAME, config.EDGE_PORT
        )
        response = requests.get(url, headers=headers, verify=False)
        self.assertEqual(200, response.status_code)
        self.assertEqual("some js", response.text)
        self.assertIn("content-type", response.headers)
        self.assertEqual("application/javascript; charset=utf-8", response.headers["content-type"])
        self.assertIn("etag", response.headers)
        self.assertEqual(with_content_type_obj["ETag"], response.headers["etag"])

        # index document
        url = "https://{}.{}:{}/test".format(
            bucket_name, constants.S3_STATIC_WEBSITE_HOSTNAME, config.EDGE_PORT
        )
        response = requests.get(url, headers=headers, verify=False)
        self.assertEqual(200, response.status_code)
        self.assertEqual("index", response.text)
        self.assertIn("content-type", response.headers)
        self.assertEqual("text/html", response.headers["content-type"])
        self.assertIn("etag", response.headers)
        self.assertEqual(index_obj["ETag"], response.headers["etag"])

        # root path test
        url = "https://{}.{}:{}/".format(
            bucket_name, constants.S3_STATIC_WEBSITE_HOSTNAME, config.EDGE_PORT
        )
        response = requests.get(url, headers=headers, verify=False)
        self.assertEqual(404, response.status_code)
        self.assertEqual("error", response.text)
        self.assertIn("content-type", response.headers)
        self.assertEqual("text/html", response.headers["content-type"])
        self.assertIn("etag", response.headers)
        self.assertEqual(error_obj["ETag"], response.headers["etag"])

        # error document
        url = "https://{}.{}:{}/something".format(
            bucket_name, constants.S3_STATIC_WEBSITE_HOSTNAME, config.EDGE_PORT
        )
        response = requests.get(url, headers=headers, verify=False)
        self.assertEqual(404, response.status_code)
        self.assertEqual("error", response.text)
        self.assertIn("content-type", response.headers)
        self.assertEqual("text/html", response.headers["content-type"])
        self.assertIn("etag", response.headers)
        self.assertEqual(error_obj["ETag"], response.headers["etag"])

        # redirect object
        url = "https://{}.{}:{}/to-be-redirected.html".format(
            bucket_name, constants.S3_STATIC_WEBSITE_HOSTNAME, config.EDGE_PORT
        )
        response = requests.get(url, headers=headers, verify=False, allow_redirects=False)
        self.assertEqual(301, response.status_code)
        self.assertIn("location", response.headers)
        self.assertEqual("actual/key.html", response.headers["location"])
        response = requests.get(url, headers=headers, verify=False)
        self.assertEqual(200, response.status_code)
        self.assertEqual(actual_key_obj["ETag"], response.headers["etag"])

    def test_s3_static_website_index(self):
        bucket_name = "test-%s" % short_uid()

        self.s3_client.create_bucket(Bucket=bucket_name)
        self.s3_client.put_object(
            Bucket=bucket_name, Key="index.html", Body="index", ContentType="text/html"
        )

        self.s3_client.put_bucket_website(
            Bucket=bucket_name,
            WebsiteConfiguration={
                "IndexDocument": {"Suffix": "index.html"},
            },
        )

        url = "https://{}.{}:{}".format(
            bucket_name, constants.S3_STATIC_WEBSITE_HOSTNAME, config.EDGE_PORT
        )

        headers = aws_stack.mock_aws_request_headers("s3")
        headers["Host"] = s3_utils.get_bucket_website_hostname(bucket_name)
        response = requests.get(url, headers=headers, verify=False)
        self.assertEqual(200, response.status_code)
        self.assertEqual("index", response.text)

    def test_s3_delete_object_with_version_id(self):
        test_1st_key = "aws/s3/testkey1.txt"
        test_2nd_key = "aws/s3/testkey2.txt"

        body = "Lorem ipsum dolor sit amet, ... " * 30

        self.s3_client.create_bucket(Bucket=TEST_BUCKET_WITH_VERSIONING)
        self.s3_client.put_bucket_versioning(
            Bucket=TEST_BUCKET_WITH_VERSIONING,
            VersioningConfiguration={"Status": "Enabled"},
        )

        # put 2 objects
        rs = self.s3_client.put_object(
            Bucket=TEST_BUCKET_WITH_VERSIONING, Key=test_1st_key, Body=body
        )
        self.s3_client.put_object(Bucket=TEST_BUCKET_WITH_VERSIONING, Key=test_2nd_key, Body=body)

        version_id = rs["VersionId"]

        # delete 1st object with version
        rs = self.s3_client.delete_objects(
            Bucket=TEST_BUCKET_WITH_VERSIONING,
            Delete={"Objects": [{"Key": test_1st_key, "VersionId": version_id}]},
        )

        deleted = rs["Deleted"][0]
        self.assertEqual(test_1st_key, deleted["Key"])
        self.assertEqual(version_id, deleted["VersionId"])

        rs = self.s3_client.list_object_versions(Bucket=TEST_BUCKET_WITH_VERSIONING)
        object_versions = [object["VersionId"] for object in rs["Versions"]]

        self.assertNotIn(version_id, object_versions)

        # clean up
        self.s3_client.put_bucket_versioning(
            Bucket=TEST_BUCKET_WITH_VERSIONING,
            VersioningConfiguration={"Status": "Disabled"},
        )
        self._delete_bucket(TEST_BUCKET_WITH_VERSIONING, [test_1st_key, test_2nd_key])

    def test_etag_on_get_object_call(self):
        self.s3_client.create_bucket(Bucket=TEST_BUCKET_NAME_2)

        body = "Lorem ipsum dolor sit amet, ... " * 30
        rs = self.s3_client.put_object(Bucket=TEST_BUCKET_NAME_2, Key=TEST_KEY_2, Body=body)
        etag = rs["ETag"]

        rs = self.s3_client.get_object(Bucket=TEST_BUCKET_NAME_2, Key=TEST_KEY_2)
        self.assertIn("ETag", rs)
        self.assertEqual(etag, rs["ETag"])
        self.assertEqual(len(body), rs["ContentLength"])

        rs = self.s3_client.get_object(
            Bucket=TEST_BUCKET_NAME_2,
            Key=TEST_KEY_2,
            Range="bytes=0-{}".format(TEST_GET_OBJECT_RANGE - 1),
        )
        self.assertIn("ETag", rs)
        self.assertEqual(etag, rs["ETag"])
        self.assertEqual(TEST_GET_OBJECT_RANGE, rs["ContentLength"])

        # clean up
        self._delete_bucket(TEST_BUCKET_NAME_2, [TEST_KEY_2])

    def test_get_object_versioning(self):
        bucket_name = "bucket-%s" % short_uid()

        self.s3_client.create_bucket(Bucket=bucket_name)
        rs = self.s3_client.list_object_versions(Bucket=bucket_name, EncodingType="url")

        self.assertEqual(200, rs["ResponseMetadata"]["HTTPStatusCode"])
        self.assertEqual(bucket_name, rs["Name"])

        # clean up
        self._delete_bucket(bucket_name, [])

    def test_bucket_versioning(self):
        self.s3_client.create_bucket(Bucket=TEST_BUCKET_WITH_VERSIONING)
        self.s3_client.put_bucket_versioning(
            Bucket=TEST_BUCKET_WITH_VERSIONING,
            VersioningConfiguration={"Status": "Enabled"},
        )

        result = self.s3_client.get_bucket_versioning(Bucket=TEST_BUCKET_WITH_VERSIONING)
        self.assertEqual("Enabled", result["Status"])

    def test_get_bucket_versioning_order(self):
        bucket_name = "version-order-%s" % short_uid()
        self.s3_client.create_bucket(Bucket=bucket_name)
        self.s3_client.put_bucket_versioning(
            Bucket=bucket_name, VersioningConfiguration={"Status": "Enabled"}
        )
        self.s3_client.put_object(Bucket=bucket_name, Key="test", Body="body")
        self.s3_client.put_object(Bucket=bucket_name, Key="test", Body="body")
        self.s3_client.put_object(Bucket=bucket_name, Key="test2", Body="body")
        rs = self.s3_client.list_object_versions(
            Bucket=bucket_name,
        )

        self.assertEqual(200, rs["ResponseMetadata"]["HTTPStatusCode"])
        self.assertEqual(bucket_name, rs["Name"])
        self.assertTrue(rs["Versions"][0]["IsLatest"])
        self.assertTrue(rs["Versions"][2]["IsLatest"])

    def test_upload_big_file(self):
        bucket_name = "bucket-big-file-%s" % short_uid()
        key1 = "test_key1"
        key2 = "test_key1"

        self.s3_client.create_bucket(Bucket=bucket_name)

        body1 = "\x01" * 10000000
        rs = self.s3_client.put_object(Bucket=bucket_name, Key=key1, Body=body1)
        self.assertEqual(200, rs["ResponseMetadata"]["HTTPStatusCode"])

        body2 = "a" * 10000000
        rs = self.s3_client.put_object(Bucket=bucket_name, Key=key2, Body=body2)
        self.assertEqual(200, rs["ResponseMetadata"]["HTTPStatusCode"])

        rs = self.s3_client.head_object(Bucket=bucket_name, Key=key1)
        self.assertEqual(len(body1), rs["ContentLength"])

        rs = self.s3_client.head_object(Bucket=bucket_name, Key=key2)
        self.assertEqual(len(body2), rs["ContentLength"])

        # clean up
        self._delete_bucket(bucket_name, [key1, key2])

    def test_s3_put_more_than_1000_items(self):
        self.s3_client.create_bucket(Bucket=TEST_BUCKET_NAME_2)
        for i in range(0, 1010, 1):
            body = "test-" + str(i)
            key = "test-key-" + str(i)
            self.s3_client.put_object(Bucket=TEST_BUCKET_NAME_2, Key=key, Body=body)

        # trying to get the last item of 1010 items added.
        resp = self.s3_client.get_object(Bucket=TEST_BUCKET_NAME_2, Key="test-key-1009")
        self.assertEqual("test-1009", to_str(resp["Body"].read()))

        # trying to get the first item of 1010 items added.
        resp = self.s3_client.get_object(Bucket=TEST_BUCKET_NAME_2, Key="test-key-0")
        self.assertEqual("test-0", to_str(resp["Body"].read()))

        resp = self.s3_client.list_objects(Bucket=TEST_BUCKET_NAME_2, MaxKeys=1010)
        self.assertEqual(1010, len(resp["Contents"]))

        resp = self.s3_client.list_objects(Bucket=TEST_BUCKET_NAME_2)
        self.assertEqual(1000, len(resp["Contents"]))
        next_marker = resp["NextMarker"]

        # Second list
        resp = self.s3_client.list_objects(Bucket=TEST_BUCKET_NAME_2, Marker=next_marker)
        self.assertEqual(10, len(resp["Contents"]))

    def test_s3_list_objects_empty_marker(self):
        bucket_name = "test" + short_uid()
        self.s3_client.create_bucket(Bucket=bucket_name)
        resp = self.s3_client.list_objects(Bucket=bucket_name, Marker="")
        self.assertEqual("", resp["Marker"])

    def test_create_bucket_with_existing_name(self):
        bucket_name = "bucket-%s" % short_uid()
        self.s3_client.create_bucket(
            Bucket=bucket_name,
            CreateBucketConfiguration={"LocationConstraint": "us-west-1"},
        )

        for loc_constraint in ["us-west-1", "us-east-1"]:
            with self.assertRaises(ClientError) as error:
                self.s3_client.create_bucket(
                    Bucket=bucket_name,
                    CreateBucketConfiguration={"LocationConstraint": loc_constraint},
                )
            self.assertIn("BucketAlreadyOwnedByYou", str(error.exception))

        self.s3_client.delete_bucket(Bucket=bucket_name)
        bucket_name = "bucket-%s" % short_uid()
        response = self.s3_client.create_bucket(
            Bucket=bucket_name,
            CreateBucketConfiguration={"LocationConstraint": "us-east-1"},
        )
        self.assertEqual(200, response["ResponseMetadata"]["HTTPStatusCode"])
        self.s3_client.delete_bucket(Bucket=bucket_name)

    def test_s3_get_deep_archive_object(self):
        bucket_name = "bucket-%s" % short_uid()
        object_key = "key-%s" % short_uid()

        self.s3_client.create_bucket(Bucket=bucket_name)

        # put DEEP_ARCHIVE object
        self.s3_client.put_object(
            Bucket=bucket_name,
            Key=object_key,
            Body="body data",
            StorageClass="DEEP_ARCHIVE",
        )

        with self.assertRaises(ClientError) as ctx:
            self.s3_client.get_object(Bucket=bucket_name, Key=object_key)

        self.assertIn("InvalidObjectState", str(ctx.exception))

        # clean up
        self._delete_bucket(bucket_name, [object_key])

    def test_s3_get_deep_archive_object_restore(self):
        bucket_name = f"bucket-{short_uid()}"
        object_key = f"key-{short_uid()}"

        self.s3_client.create_bucket(Bucket=bucket_name)

        # put DEEP_ARCHIVE object
        self.s3_client.put_object(
            Bucket=bucket_name,
            Key=object_key,
            Body="body data",
            StorageClass="DEEP_ARCHIVE",
        )

        with self.assertRaises(ClientError) as ctx:
            self.s3_client.get_object(Bucket=bucket_name, Key=object_key)

        self.assertIn("InvalidObjectState", str(ctx.exception))

        # put DEEP_ARCHIVE object
        self.s3_client.restore_object(
            Bucket=bucket_name,
            Key=object_key,
            RestoreRequest={
                "Days": 30,
                "GlacierJobParameters": {"Tier": "Bulk"},
                "Tier": "Bulk",
            },
        )

        response = self.s3_client.get_object(Bucket=bucket_name, Key=object_key)

        self.assertIn("etag", response.get("ResponseMetadata").get("HTTPHeaders"))

        # clean up
        self._delete_bucket(bucket_name, [object_key])

    def test_s3_batch_delete_objects_using_requests(self):
        bucket_name = "bucket-%s" % short_uid()
        object_key_1 = "key-%s" % short_uid()
        object_key_2 = "key-%s" % short_uid()

        self.s3_client.create_bucket(Bucket=bucket_name)
        self.s3_client.put_object(Bucket=bucket_name, Key=object_key_1, Body="This body document")
        self.s3_client.put_object(Bucket=bucket_name, Key=object_key_2, Body="This body document")

        base_url = (
            f"{get_service_protocol()}://{config.LOCALSTACK_HOSTNAME}:{config.service_port('s3')}"
        )
        url = "{}/{}?delete=".format(base_url, bucket_name)
        r = requests.post(url=url, data=BATCH_DELETE_BODY % (object_key_1, object_key_2))

        self.assertEqual(200, r.status_code)

        s3_resource = aws_stack.connect_to_resource("s3")
        bucket = s3_resource.Bucket(bucket_name)

        total_keys = sum(1 for _ in bucket.objects.all())
        self.assertEqual(0, total_keys)

        # clean up
        self._delete_bucket(bucket_name, [])

    # Note: This test may have side effects (via `s3_client.meta.events.register(..)`) and
    # may not be suitable for parallel execution
    def test_presign_with_query_params(self):
        def add_query_param(self, request, **kwargs):
            request.url += "requestedBy=abcDEF123"

        bucket_name = short_uid()
        s3_client = aws_stack.create_external_boto_client("s3")
        s3_presign = boto3.client(
            "s3",
            endpoint_url=config.get_edge_url(),
            aws_access_key_id="test",
            aws_secret_access_key="test",
            config=Config(signature_version="s3v4"),
        )

        s3_client.create_bucket(Bucket=bucket_name)
        s3_client.put_object(Body="test-value", Bucket=bucket_name, Key="test")
        response = s3_client.head_object(Bucket=bucket_name, Key="test")
        s3_client.meta.events.register("before-sign.s3.GetObject", add_query_param)
        try:
            presign_url = s3_presign.generate_presigned_url(
                ClientMethod="get_object",
                Params={"Bucket": bucket_name, "Key": "test"},
                ExpiresIn=86400,
            )
            response = requests.get(presign_url)
            self.assertEqual(b"test-value", response._content)
        finally:
            s3_client.meta.events.unregister("before-sign.s3.GetObject", add_query_param)

    @patch.object(config, "S3_SKIP_SIGNATURE_VALIDATION", False)
    def test_presigned_url_signature_authentication(self):
        client = boto3.client(
            "s3",
            endpoint_url=config.get_edge_url(),
            config=Config(signature_version="s3"),
            aws_access_key_id=TEST_AWS_ACCESS_KEY_ID,
            aws_secret_access_key=TEST_AWS_SECRET_ACCESS_KEY,
        )
        client_v4 = boto3.client(
            "s3",
            endpoint_url=config.get_edge_url(),
            config=Config(signature_version="s3v4"),
            aws_access_key_id=TEST_AWS_ACCESS_KEY_ID,
            aws_secret_access_key=TEST_AWS_SECRET_ACCESS_KEY,
        )
        bucket_name = "presign-%s" % short_uid()
        url_prefix = "{}/{}".format(
            config.get_edge_url(),
            bucket_name,
        )
        self.run_presigned_url_signature_authentication(client, client_v4, bucket_name, url_prefix)

    @patch.object(config, "S3_SKIP_SIGNATURE_VALIDATION", False)
    def test_presigned_url_signature_authentication_virtual_host_addressing(self):
        virtual_endpoint = "{}://{}:{}".format(
            config.get_protocol(),
            S3_VIRTUAL_HOSTNAME,
            config.EDGE_PORT,
        )
        bucket_name = "presign-%s" % short_uid()
        url_prefix = "{}://{}.{}:{}".format(
            config.get_protocol(),
            bucket_name,
            S3_VIRTUAL_HOSTNAME,
            config.EDGE_PORT,
        )
        client = boto3.client(
            "s3",
            endpoint_url=virtual_endpoint,
            config=Config(signature_version="s3", s3={"addressing_style": "virtual"}),
            aws_access_key_id=TEST_AWS_ACCESS_KEY_ID,
            aws_secret_access_key=TEST_AWS_SECRET_ACCESS_KEY,
        )
        client_v4 = boto3.client(
            "s3",
            endpoint_url=virtual_endpoint,
            config=Config(signature_version="s3v4", s3={"addressing_style": "virtual"}),
            aws_access_key_id=TEST_AWS_ACCESS_KEY_ID,
            aws_secret_access_key=TEST_AWS_SECRET_ACCESS_KEY,
        )
        self.run_presigned_url_signature_authentication(client, client_v4, bucket_name, url_prefix)

    def run_presigned_url_signature_authentication(
        self, client, client_v4, bucket_name, url_prefix
    ):
        object_key = "temp.txt"
        object_data = "this should be found in when you download {}.".format(object_key)
        expires = 4

        def make_v2_url_invalid(url):
            parsed = urlparse(url)
            query_params = parse_qs(parsed.query)
            url = "{}/{}?AWSAccessKeyId={}&Signature={}&Expires={}".format(
                url_prefix,
                object_key,
                "test",
                query_params["Signature"][0],
                query_params["Expires"][0],
            )
            return url

        def make_v4_url_invalid(url):
            parsed = urlparse(url)
            query_params = parse_qs(parsed.query)
            url = (
                "{}/{}?X-Amz-Algorithm=AWS4-HMAC-SHA256&"
                "X-Amz-Credential={}&X-Amz-Date={}&"
                "X-Amz-Expires={}&X-Amz-SignedHeaders=host&"
                "X-Amz-Signature={}"
            ).format(
                url_prefix,
                object_key,
                quote(query_params["X-Amz-Credential"][0]).replace("/", "%2F"),
                query_params["X-Amz-Date"][0],
                query_params["X-Amz-Expires"][0],
                query_params["X-Amz-Signature"][0],
            )
            return url

        client.create_bucket(Bucket=bucket_name)
        client.put_object(Key=object_key, Bucket=bucket_name, Body="123")

        # GET requests
        presign_get_url = client.generate_presigned_url(
            "get_object",
            Params={"Bucket": bucket_name, "Key": object_key},
            ExpiresIn=expires,
        )

        presign_get_url_v4 = client_v4.generate_presigned_url(
            "get_object",
            Params={"Bucket": bucket_name, "Key": object_key},
            ExpiresIn=expires,
        )

        # Valid request
        response = requests.get(presign_get_url)
        self.assertEqual(200, response.status_code)

        response = requests.get(presign_get_url_v4)
        self.assertEqual(200, response.status_code)

        presign_get_url = client.generate_presigned_url(
            "get_object",
            Params={
                "Bucket": bucket_name,
                "Key": object_key,
                "ResponseContentType": "text/plain",
                "ResponseContentDisposition": "attachment;  filename=test.txt",
            },
            ExpiresIn=expires,
        )

        presign_get_url_v4 = client_v4.generate_presigned_url(
            "get_object",
            Params={
                "Bucket": bucket_name,
                "Key": object_key,
                "ResponseContentType": "text/plain",
            },
            ExpiresIn=expires,
        )

        # Valid request
        response = requests.get(presign_get_url)
        self.assertEqual(200, response.status_code)

        response = requests.get(presign_get_url_v4)
        self.assertEqual(200, response.status_code)

        # Invalid request
        url = make_v2_url_invalid(presign_get_url)
        response = requests.get(
            url, data=object_data, headers={"Content-Type": "my-fake-content/type"}
        )
        self.assertEqual(403, response.status_code)

        url = make_v4_url_invalid(presign_get_url_v4)
        response = requests.get(url, headers={"Content-Type": "my-fake-content/type"})
        self.assertEqual(403, response.status_code)

        # PUT Requests
        presign_put_url = client.generate_presigned_url(
            "put_object",
            Params={"Bucket": bucket_name, "Key": object_key},
            ExpiresIn=expires,
        )

        presign_put_url_v4 = client_v4.generate_presigned_url(
            "put_object",
            Params={"Bucket": bucket_name, "Key": object_key},
            ExpiresIn=expires,
        )

        # Valid request
        response = requests.put(presign_put_url, data=object_data)
        self.assertEqual(200, response.status_code)

        response = requests.put(presign_put_url_v4, data=object_data)
        self.assertEqual(200, response.status_code)

        presign_put_url = client.generate_presigned_url(
            "put_object",
            Params={
                "Bucket": bucket_name,
                "Key": object_key,
                "ContentType": "text/plain",
            },
            ExpiresIn=expires,
        )

        presign_put_url_v4 = client_v4.generate_presigned_url(
            "put_object",
            Params={
                "Bucket": bucket_name,
                "Key": object_key,
                "ContentType": "text/plain",
            },
            ExpiresIn=expires,
        )

        # Valid request
        response = requests.put(
            presign_put_url, data=object_data, headers={"Content-Type": "text/plain"}
        )
        self.assertEqual(200, response.status_code)

        response = requests.put(
            presign_put_url_v4, data=object_data, headers={"Content-Type": "text/plain"}
        )
        self.assertEqual(200, response.status_code)

        # Invalid request
        url = make_v2_url_invalid(presign_put_url)
        response = requests.put(
            url, data=object_data, headers={"Content-Type": "my-fake-content/type"}
        )
        self.assertEqual(403, response.status_code)

        url = make_v4_url_invalid(presign_put_url_v4)
        response = requests.put(
            url, data=object_data, headers={"Content-Type": "my-fake-content/type"}
        )
        self.assertEqual(403, response.status_code)

        # DELETE Requests
        presign_delete_url = client.generate_presigned_url(
            "delete_object",
            Params={"Bucket": bucket_name, "Key": object_key},
            ExpiresIn=expires,
        )

        presign_delete_url_v4 = client_v4.generate_presigned_url(
            "delete_object",
            Params={"Bucket": bucket_name, "Key": object_key},
            ExpiresIn=expires,
        )

        # Valid request

        response = requests.delete(presign_delete_url)
        self.assertEqual(204, response.status_code)

        response = requests.delete(presign_delete_url_v4)
        self.assertEqual(204, response.status_code)

        presign_delete_url = client.generate_presigned_url(
            "delete_object",
            Params={"Bucket": bucket_name, "Key": object_key, "VersionId": "1"},
            ExpiresIn=expires,
        )

        presign_delete_url_v4 = client_v4.generate_presigned_url(
            "delete_object",
            Params={"Bucket": bucket_name, "Key": object_key, "VersionId": "1"},
            ExpiresIn=expires,
        )

        # Valid request
        response = requests.delete(presign_delete_url)
        self.assertEqual(204, response.status_code)

        response = requests.delete(presign_delete_url_v4)
        self.assertEqual(204, response.status_code)

        # Invalid request
        url = make_v2_url_invalid(presign_delete_url)
        response = requests.delete(url)
        self.assertEqual(403, response.status_code)

        url = make_v4_url_invalid(presign_delete_url_v4)
        response = requests.delete(url)
        self.assertEqual(403, response.status_code)

        # Expired requests
        time.sleep(4)

        # GET
        response = requests.get(presign_get_url)
        self.assertEqual(403, response.status_code)
        response = requests.get(presign_get_url_v4)
        self.assertEqual(403, response.status_code)

        # PUT
        response = requests.put(
            presign_put_url, data=object_data, headers={"Content-Type": "text/plain"}
        )
        self.assertEqual(403, response.status_code)
        response = requests.put(
            presign_put_url_v4, data=object_data, headers={"Content-Type": "text/plain"}
        )
        self.assertEqual(403, response.status_code)

        # DELETE
        response = requests.delete(presign_delete_url)
        self.assertEqual(403, response.status_code)
        response = requests.delete(presign_delete_url_v4)
        self.assertEqual(403, response.status_code)

        # Multipart uploading
        response = self._perform_multipart_upload_with_presign(bucket_name, object_key, client)
        self.assertEqual(200, response["ResponseMetadata"]["HTTPStatusCode"])
        response = self._perform_multipart_upload_with_presign(bucket_name, object_key, client_v4)
        self.assertEqual(200, response["ResponseMetadata"]["HTTPStatusCode"])

        client.delete_object(Bucket=bucket_name, Key=object_key)
        client.delete_bucket(Bucket=bucket_name)

    # TODO
    @pytest.mark.skip_offline
    def test_s3_lambda_integration(self):
        if not use_docker():
            return
        temp_folder = new_tmp_dir()
        handler_file = os.path.join(
            THIS_FOLDER, "awslambda", "functions", "lambda_s3_integration.js"
        )
        shutil.copy(handler_file, temp_folder)
        run("cd %s; npm i @aws-sdk/client-s3; npm i @aws-sdk/s3-request-presigner" % temp_folder)

        function_name = "func-integration-%s" % short_uid()
        lambda_client = aws_stack.create_external_boto_client("lambda")
        s3_client = aws_stack.create_external_boto_client("s3")

        testutil.create_lambda_function(
            func_name=function_name,
            zip_file=testutil.create_zip_file(temp_folder, get_content=True),
            runtime=LAMBDA_RUNTIME_NODEJS14X,
            handler="lambda_s3_integration.handler",
        )
        s3_client.create_bucket(Bucket=function_name)

        response = lambda_client.invoke(FunctionName=function_name)
        presigned_url = response["Payload"].read()
        presigned_url = json.loads(to_str(presigned_url))["body"].strip('"')

        response = requests.put(presigned_url, verify=False)
        response = s3_client.head_object(Bucket=function_name, Key="key.png")
        self.assertEqual(200, response["ResponseMetadata"]["HTTPStatusCode"])

        s3_client.delete_object(Bucket=function_name, Key="key.png")
        s3_client.delete_bucket(Bucket=function_name)

    # TODO -> not sure if this test makes sense in the future..
    def test_presign_port_permutation(self):
        bucket_name = short_uid()
        port1 = 443
        port2 = 4566
        s3_client = aws_stack.create_external_boto_client("s3")

        s3_presign = boto3.client(
            "s3",
            endpoint_url="http://127.0.0.1:%s" % port1,
            aws_access_key_id="test",
            aws_secret_access_key="test",
            config=Config(signature_version="s3v4"),
        )

        s3_client.create_bucket(Bucket=bucket_name)
        s3_client.put_object(Body="test-value", Bucket=bucket_name, Key="test")
        response = s3_client.head_object(Bucket=bucket_name, Key="test")

        presign_url = s3_presign.generate_presigned_url(
            ClientMethod="get_object",
            Params={"Bucket": bucket_name, "Key": "test"},
            ExpiresIn=86400,
        )
        presign_url = presign_url.replace(":%s" % port1, ":%s" % port2)

        response = requests.get(presign_url)
        self.assertEqual(b"test-value", response._content)

    # ---------------
    # HELPER METHODS
    # ---------------

    def _delete_bucket(self, bucket_name, keys=None):
        if keys is None:
            keys = []
        keys = keys if isinstance(keys, list) else [keys]
        objects = [{"Key": k} for k in keys]
        if objects:
            self.s3_client.delete_objects(Bucket=bucket_name, Delete={"Objects": objects})
        self.s3_client.delete_bucket(Bucket=bucket_name)

    def _perform_multipart_upload(self, bucket, key, data=None, zip=False, acl=None):
        kwargs = {"ACL": acl} if acl else {}
        multipart_upload_dict = self.s3_client.create_multipart_upload(
            Bucket=bucket, Key=key, **kwargs
        )
        upload_id = multipart_upload_dict["UploadId"]

        # Write contents to memory rather than a file.
        data = data or (5 * short_uid())
        data = to_bytes(data)
        upload_file_object = BytesIO(data)
        if zip:
            upload_file_object = BytesIO()
            with gzip.GzipFile(fileobj=upload_file_object, mode="w") as filestream:
                filestream.write(data)

        response = self.s3_client.upload_part(
            Bucket=bucket,
            Key=key,
            Body=upload_file_object,
            PartNumber=1,
            UploadId=upload_id,
        )

        multipart_upload_parts = [{"ETag": response["ETag"], "PartNumber": 1}]

        return self.s3_client.complete_multipart_upload(
            Bucket=bucket,
            Key=key,
            MultipartUpload={"Parts": multipart_upload_parts},
            UploadId=upload_id,
        )

    def _perform_multipart_upload_with_presign(
        self, bucket, key, s3_client=None, data=None, zip=False, acl=None
    ):
        if not s3_client:
            s3_client = self.s3_client

        kwargs = {"ACL": acl} if acl else {}
        multipart_upload_dict = self.s3_client.create_multipart_upload(
            Bucket=bucket, Key=key, **kwargs
        )
        upload_id = multipart_upload_dict["UploadId"]

        # Write contents to memory rather than a file.
        data = data or (5 * short_uid())
        data = to_bytes(data)
        upload_file_object = BytesIO(data)
        if zip:
            upload_file_object = BytesIO()
            with gzip.GzipFile(fileobj=upload_file_object, mode="w") as filestream:
                filestream.write(data)

        signed_url = s3_client.generate_presigned_url(
            ClientMethod="upload_part",
            Params={
                "Bucket": bucket,
                "Key": key,
                "UploadId": upload_id,
                "PartNumber": 1,
            },
        )
        response = requests.put(signed_url, data=upload_file_object)

        multipart_upload_parts = [{"ETag": response.headers["ETag"], "PartNumber": 1}]

        return s3_client.complete_multipart_upload(
            Bucket=bucket,
            Key=key,
            MultipartUpload={"Parts": multipart_upload_parts},
            UploadId=upload_id,
        )

    def _get_test_client(self, region_name="us-east-1"):
        return boto3.client(
            "s3",
            endpoint_url=config.get_edge_url(),
            aws_access_key_id=TEST_AWS_ACCESS_KEY_ID,
            aws_secret_access_key=TEST_AWS_SECRET_ACCESS_KEY,
            region_name=region_name,
        )


# TODO
@pytest.mark.only_localstack
def test_put_object_with_md5_and_chunk_signature(s3_client):
    # can't make it work with AWS_CLOUD
    # based on https://github.com/localstack/localstack/issues/4987
    bucket_name = "bucket-%s" % short_uid()
    object_key = "test-runtime.properties"
    object_data = (
        "#20211122+0100\n"
        "#Mon Nov 22 20:10:44 CET 2021\n"
        "last.sync.url.test-space-key=2822a50f-4992-425a-b8fb-923735a9ddff317e3479-5907-46cf-b33a-60da9709274f\n"
    )
    object_data_chunked = (
        "93;chunk-signature=5be6b2d473e96bb9f297444da60bdf0ff8f5d2e211e1d551b3cf3646c0946641\r\n"
        "%s"
        "\r\n0;chunk-signature=bd5c830b94346b57ddc8805ba26c44a122256c207014433bf6579b0985f21df7\r\n\r\n"
        % object_data
    )
    content_md5 = base64.b64encode(hashlib.md5(object_data.encode()).digest()).decode()
    headers = {
        "Content-Md5": content_md5,
        "Content-Type": "application/octet-stream",
        "User-Agent": (
            "aws-sdk-java/1.11.951 Mac_OS_X/10.15.7 OpenJDK_64-Bit_Server_VM/11.0.11+9-LTS "
            "java/11.0.11 scala/2.13.6 kotlin/1.5.31 vendor/Amazon.com_Inc."
        ),
        "X-Amz-Content-Sha256": "STREAMING-AWS4-HMAC-SHA256-PAYLOAD",
        "X-Amz-Date": "20211122T191045Z",
        "X-Amz-Decoded-Content-Length": str(len(object_data)),
        "Content-Length": str(len(object_data_chunked)),
        "Connection": "Keep-Alive",
        "Expect": "100-continue",
    }

    s3_client.create_bucket(Bucket=bucket_name)
    url = s3_client.generate_presigned_url(
        "put_object",
        Params={
            "Bucket": bucket_name,
            "Key": object_key,
            "ContentType": "application/octet-stream",
            "ContentMD5": content_md5,
        },
    )
    result = requests.put(url, data=object_data_chunked, headers=headers)
    assert result.status_code == 200, (result, result.content)
