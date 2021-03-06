from __future__ import absolute_import
import atexit
import base64
import bisect
import brotli
import calendar
import cgi
import codecs
import collections
import datetime
import hashlib
import heapq
import hmac
import itertools
import json
import logging
import mimetypes
import os
import pkg_resources
import pkgutil
import pprint
import re
import requests
import shutil
import six
import six.moves.urllib.parse as urlparse
import six.moves.html_parser
import socket
import ssl
import surt
import sys
import time
import webencodings
import yaml
import zlib
import multiprocessing
from heapq import merge
from argparse import ArgumentParser, RawTextHelpFormatter
from bisect import insort
from collections import deque
from copy import copy
from datetime import datetime, timedelta
from distutils.util import strtobool
from email.utils import parsedate, formatdate
from io import open, BytesIO
from itertools import chain
from jinja2 import Environment
from jinja2 import FileSystemLoader, PackageLoader, ChoiceLoader
from pkg_resources import resource_string
from pprint import pformat
from redis import StrictRedis
from requests import request as live_request
from shutil import rmtree
from six import iteritems
from six import StringIO
from six import text_type
from six.moves.html_parser import HTMLParser
from six.moves.http_cookies import SimpleCookie, CookieError
from six.moves import zip, range, map
from six.moves.urllib.error import HTTPError
from six.moves.urllib.parse import parse_qs, quote
from six.moves.urllib.parse import quote_plus, unquote_plus
from six.moves.urllib.parse import urlencode
from six.moves.urllib.parse import urljoin, urlsplit, urlunsplit
from six.moves.urllib.request import pathname2url, url2pathname
from six.moves.urllib.request import urlopen, Request
from tempfile import NamedTemporaryFile, mkdtemp
from tempfile import SpooledTemporaryFile
from watchdog.events import RegexMatchingEventHandler
from watchdog.observers import Observer
from json import loads as json_decode
from json import dumps as json_encode
# ensure we are loading the config files nicely
from pywb import DEFAULT_CONFIG, DEFAULT_RULES_FILE, DEFAULT_CONFIG_FILE

six.moves.html_parser.unescape = lambda x: x

try:  # pragma: no cover
    import uwsgi

    uwsgi_cache = True
except ImportError:
    uwsgi_cache = False

if os.environ.get('GEVENT_MONKEY_PATCH') == '1':  # pragma: no cover
    # Use gevent if available
    try:
        from gevent.monkey import patch_all

        patch_all()
        print('gevent patched!')
    except Exception as e:
        pass

try:
    from boto import connect_s3

    s3_avail = True
except ImportError:  # pragma: no cover
    s3_avail = False

# Use ujson if available
try:
    from ujson import dumps as ujson_dumps

    try:
        assert (ujson_dumps('http://example.com/',
                            escape_forward_slashes=False) ==
                '"http://example.com/"')
    except Exception as e:  # pragma: no cover
        sys.stderr.write('ujson w/o forward-slash escaping not available,\
defaulting to regular json\n')
        raise


    def json_encode(obj):
        return ujson_dumps(obj, escape_forward_slashes=False)

except:  # pragma: no cover
    from json import dumps as json_encode

try:  # pragma: no cover
    from collections import OrderedDict
except ImportError:  # pragma: no cover
    from ordereddict import OrderedDict

# =============================================================================
EXT_REGEX = '.*\.w?arc(\.gz)?$'

keep_running = True

# =================================================================


DEFAULT_PORT = 8080

WRAP_WIDTH = 80

FILTERS = {}

# =================================================================


DATE_TIMESPLIT = re.compile(r'[^\d]')

TIMESTAMP_14 = '%Y%m%d%H%M%S'
ISO_DT = '%Y-%m-%dT%H:%M:%SZ'

PAD_14_DOWN = '10000101000000'
PAD_14_UP = '29991231235959'
PAD_6_UP = '299912'

LINK_FORMAT = 'application/link-format'

# =================================================================
URLKEY = 'urlkey'
TIMESTAMP = 'timestamp'
ORIGINAL = 'url'
MIMETYPE = 'mime'
STATUSCODE = 'status'
DIGEST = 'digest'
REDIRECT = 'redirect'
ROBOTFLAGS = 'robotflags'
LENGTH = 'length'
OFFSET = 'offset'
FILENAME = 'filename'

ORIG_LENGTH = 'orig.length'
ORIG_OFFSET = 'orig.offset'
ORIG_FILENAME = 'orig.filename'


# =================================================================
# begin pywb.utils.wbexception
class WbException(Exception):
    def __init__(self, msg=None, url=None):
        Exception.__init__(self, msg)
        self.msg = msg
        self.url = url


class AccessException(WbException):
    def status(self):
        return '403 Access Denied'


class BadRequestException(WbException):
    def status(self):
        return '400 Bad Request'


class NotFoundException(WbException):
    def status(self):
        return '404 Not Found'


class LiveResourceException(WbException):
    def status(self):
        return '400 Bad Live Resource'


class CDXException(WbException):
    def status(self):
        return '400 Bad Request'


# End pywb.utils.wbexception
# =================================================================

# =================================================================
# begin pywb.utils.loaders

# =================================================================
def is_http(filename):
    return filename.startswith(('http://', 'https://'))


# =================================================================
def to_file_url(filename):
    """ Convert a filename to a file:// url
    """
    url = os.path.abspath(filename)
    url = urljoin('file:', pathname2url(url))
    return url


# =================================================================
def load_yaml_config(config_file):
    config = None
    configdata = None
    try:
        configdata = BlockLoader().load(config_file)
        config = yaml.load(configdata)
    finally:
        configdata.close()
        if configdata:
            configdata.close()

    return config


# =================================================================
def to_native_str(value, encoding='iso-8859-1', func=lambda x: x):
    if isinstance(value, str):
        return value

    if six.PY3 and isinstance(value, six.binary_type):  # pragma: no cover
        return func(value.decode(encoding))
    elif six.PY2 and isinstance(value, six.text_type):  # pragma: no cover
        return func(value.encode(encoding))


# =================================================================
def extract_post_query(method, mime, length, stream,
                       buffered_stream=None,
                       environ=None):
    """
    Extract a url-encoded form POST from stream
    content length, return None
    Attempt to decode application/x-www-form-urlencoded or multipart/*,
    otherwise read whole block and b64encode
    """
    if method.upper() != 'POST':
        return None

    try:
        length = int(length)
    except (ValueError, TypeError):
        return None

    if length <= 0:
        return None

    post_query = b''

    while length > 0:
        buff = stream.read(length)
        length -= len(buff)

        if not buff:
            break

        post_query += buff

    if buffered_stream:
        buffered_stream.write(post_query)
        buffered_stream.seek(0)

    if not mime:
        mime = ''

    if mime.startswith('application/x-www-form-urlencoded'):
        post_query = to_native_str(post_query)
        post_query = unquote_plus(post_query)

    elif mime.startswith('multipart/'):
        env = {'REQUEST_METHOD': 'POST',
               'CONTENT_TYPE': mime,
               'CONTENT_LENGTH': len(post_query)}

        args = dict(fp=BytesIO(post_query),
                    environ=env,
                    keep_blank_values=True)

        if six.PY3:
            args['encoding'] = 'utf-8'

        data = cgi.FieldStorage(**args)

        values = []
        for item in data.list:
            values.append((item.name, item.value))

        post_query = urlencode(values, True)

    elif mime.startswith('application/x-amf'):
        post_query = amf_parse(post_query, environ)

    else:
        post_query = base64.b64encode(post_query)
        post_query = to_native_str(post_query)
        post_query = '&__wb_post_data=' + post_query

    return post_query


# =================================================================
def amf_parse(string, environ):
    try:
        from pyamf import remoting

        res = remoting.decode(BytesIO(string))

        # print(res)
        body = res.bodies[0][1].body[0]

        values = {}

        if hasattr(body, 'body'):
            values['body'] = body.body

        if hasattr(body, 'source'):
            values['source'] = body.source

        if hasattr(body, 'operation'):
            values['op'] = body.operation

        if environ is not None:
            environ['pywb.inputdata'] = res

        query = urlencode(values)
        # print(query)
        return query

    except Exception as e:
        import traceback
        traceback.print_exc()
        print(e)
        return None


# =================================================================
def append_post_query(url, post_query):
    if not post_query:
        return url

    if '?' not in url:
        url += '?'
    else:
        url += '&'

    url += post_query
    return url


# =================================================================
def extract_client_cookie(env, cookie_name):
    cookie_header = env.get('HTTP_COOKIE')
    if not cookie_header:
        return None

    # attempt to extract cookie_name only
    inx = cookie_header.find(cookie_name)
    if inx < 0:
        return None

    end_inx = cookie_header.find(';', inx)
    if end_inx > 0:
        value = cookie_header[inx:end_inx]
    else:
        value = cookie_header[inx:]

    value = value.split('=')
    if len(value) < 2:
        return None

    value = value[1].strip()
    return value


# =================================================================
def read_last_line(fh, offset=256):
    """ Read last line from a seekable file. Start reading
    from buff before end of file, and double backwards seek
    until line break is found. If reached beginning of file
    (no lines), just return whole file
    """
    fh.seek(0, 2)
    size = fh.tell()

    while offset < size:
        fh.seek(-offset, 2)
        lines = fh.readlines()
        if len(lines) > 1:
            return lines[-1]
        offset *= 2

    fh.seek(0, 0)
    return fh.readlines()[-1]


# =================================================================
class BaseLoader(object):
    def __init__(self, **kwargs):
        pass

    def load(self, url, offset=0, length=-1):
        raise NotImplemented()


# =================================================================
class BlockLoader(BaseLoader):
    """
    a loader which can stream blocks of content
    given a uri, offset and optional length.
    Currently supports: http/https and file/local file system
    """

    loaders = {}
    profile_loader = None

    def __init__(self, **kwargs):
        self.cached = {}
        self.kwargs = kwargs

    def load(self, url, offset=0, length=-1):
        loader, url = self._get_loader_for_url(url)
        return loader.load(url, offset, length)

    def _get_loader_for_url(self, url):
        """
        Determine loading method based on uri
        """
        parts = url.split('://', 1)
        if len(parts) < 2:
            type_ = 'file'
        else:
            type_ = parts[0]

        if '+' in type_:
            profile_name, scheme = type_.split('+', 1)
            if len(parts) == 2:
                url = scheme + '://' + parts[1]
        else:
            profile_name = ''
            scheme = type_

        loader = self.cached.get(type_)
        if loader:
            return loader, url

        loader_cls = self._get_loader_class_for_type(scheme)

        if not loader_cls:
            raise IOError('No Loader for type: ' + scheme)

        profile = self.kwargs

        if self.profile_loader:
            profile = self.profile_loader(profile_name, scheme)

        loader = loader_cls(**profile)

        self.cached[type_] = loader
        return loader, url

    def _get_loader_class_for_type(self, type_):
        loader_cls = self.loaders.get(type_)
        return loader_cls

    @staticmethod
    def init_default_loaders():
        BlockLoader.loaders['http'] = HttpLoader
        BlockLoader.loaders['https'] = HttpLoader
        BlockLoader.loaders['s3'] = S3Loader
        BlockLoader.loaders['file'] = LocalFileLoader

    @staticmethod
    def set_profile_loader(src):
        BlockLoader.profile_loader = src

    @staticmethod
    def _make_range_header(offset, length):
        if length > 0:
            range_header = 'bytes={0}-{1}'.format(offset, offset + length - 1)
        else:
            range_header = 'bytes={0}-'.format(offset)

        return range_header


# =================================================================
class LocalFileLoader(BaseLoader):
    def load(self, url, offset=0, length=-1):
        """
        Load a file-like reader from the local file system
        """

        # if starting with . or /, can only be a file path..
        file_only = url.startswith(('/', '.'))

        # convert to filename
        if url.startswith('file://'):
            file_only = True
            url = url2pathname(url[len('file://'):])

        try:
            # first, try as file
            afile = open(url, 'rb')

        except IOError:
            if file_only:
                raise

            # then, try as package.path/file
            pkg_split = url.split('/', 1)
            if len(pkg_split) == 1:
                raise

            afile = pkg_resources.resource_stream(pkg_split[0],
                                                  pkg_split[1])

        if offset > 0:
            afile.seek(offset)

        if length >= 0:
            return LimitReader(afile, length)
        else:
            return afile


# =================================================================
class HttpLoader(BaseLoader):
    def __init__(self, **kwargs):
        self.cookie_maker = kwargs.get('cookie_maker')
        if not self.cookie_maker:
            self.cookie_maker = kwargs.get('cookie')
        self.session = None

    def load(self, url, offset, length):
        """
        Load a file-like reader over http using range requests
        and an optional cookie created via a cookie_maker
        """
        headers = {}
        if offset != 0 or length != -1:
            headers['Range'] = BlockLoader._make_range_header(offset, length)

        if self.cookie_maker:
            if isinstance(self.cookie_maker, six.string_types):
                headers['Cookie'] = self.cookie_maker
            else:
                headers['Cookie'] = self.cookie_maker.make()

        if not self.session:
            self.session = requests.Session()

        r = self.session.get(url, headers=headers, stream=True)
        return r.raw


# =================================================================
class S3Loader(BaseLoader):
    def __init__(self, **kwargs):
        self.s3conn = None
        self.aws_access_key_id = kwargs.get('aws_access_key_id')
        self.aws_secret_access_key = kwargs.get('aws_secret_access_key')

    def load(self, url, offset, length):
        if not s3_avail:  # pragma: no cover
            raise IOError('To load from s3 paths, ' +
                          'you must install boto: pip install boto')

        aws_access_key_id = self.aws_access_key_id
        aws_secret_access_key = self.aws_secret_access_key

        parts = urlsplit(url)

        if parts.username and parts.password:
            aws_access_key_id = unquote_plus(parts.username)
            aws_secret_access_key = unquote_plus(parts.password)
            bucket_name = parts.netloc.split('@', 1)[-1]
        else:
            bucket_name = parts.netloc

        if not self.s3conn:
            try:
                self.s3conn = connect_s3(aws_access_key_id, aws_secret_access_key)
            except Exception:  # pragma: no cover
                self.s3conn = connect_s3(anon=True)

        bucket = self.s3conn.get_bucket(bucket_name)

        key = bucket.get_key(parts.path)

        if offset == 0 and length == -1:
            headers = {}
        else:
            headers = {'Range': BlockLoader._make_range_header(offset, length)}

        # Read range
        key.open_read(headers=headers)
        return key


# =================================================================
# Signed Cookie-Maker
# =================================================================

class HMACCookieMaker(object):
    """
    Utility class to produce signed HMAC digest cookies
    to be used with each http request
    """

    def __init__(self, key, name, duration=10):
        self.key = key
        self.name = name
        # duration in seconds
        self.duration = duration

    def make(self, extra_id=''):
        expire = str(int(time.time() + self.duration))

        if extra_id:
            msg = extra_id + '-' + expire
        else:
            msg = expire

        hmacdigest = hmac.new(self.key.encode('utf-8'), msg.encode('utf-8'))
        hexdigest = hmacdigest.hexdigest()

        if extra_id:
            cookie = '{0}-{1}={2}-{3}'.format(self.name, extra_id,
                                              expire, hexdigest)
        else:
            cookie = '{0}={1}-{2}'.format(self.name, expire, hexdigest)

        return cookie


# =================================================================
# Limit Reader
# =================================================================
class LimitReader(object):
    """
    A reader which will not read more than specified limit
    """

    def __init__(self, stream, limit):
        self.stream = stream
        self.limit = limit

    def read(self, length=None):
        if length is not None:
            length = min(length, self.limit)
        else:
            length = self.limit

        if length == 0:
            return b''

        buff = self.stream.read(length)
        self.limit -= len(buff)
        return buff

    def readline(self, length=None):
        if length is not None:
            length = min(length, self.limit)
        else:
            length = self.limit

        if length == 0:
            return b''

        buff = self.stream.readline(length)
        self.limit -= len(buff)
        return buff

    def close(self):
        self.stream.close()

    @staticmethod
    def wrap_stream(stream, content_length):
        """
        If given content_length is an int > 0, wrap the stream
        in a LimitReader. Otherwise, return the stream unaltered
        """
        try:
            content_length = int(content_length)
            if content_length >= 0:
                # optimize: if already a LimitStream, set limit to
                # the smaller of the two limits
                if isinstance(stream, LimitReader):
                    stream.limit = min(stream.limit, content_length)
                else:
                    stream = LimitReader(stream, content_length)

        except (ValueError, TypeError):
            pass

        return stream


BlockLoader.init_default_loaders()


# ============================================================================

# end pywb.utils.loaders
# ============================================================================


# begin pywb.utils.timeutils

def iso_date_to_datetime(string):
    """
    >>> iso_date_to_datetime('2013-12-26T10:11:12Z')
    datetime.datetime(2013, 12, 26, 10, 11, 12)

    >>> iso_date_to_datetime('2013-12-26T10:11:12Z')
    datetime.datetime(2013, 12, 26, 10, 11, 12)
     """

    nums = DATE_TIMESPLIT.split(string)
    if nums[-1] == '':
        nums = nums[:-1]

    the_datetime = datetime.datetime(*map(int, nums))
    return the_datetime


def http_date_to_datetime(string):
    """
    >>> http_date_to_datetime('Thu, 26 Dec 2013 09:50:10 GMT')
    datetime.datetime(2013, 12, 26, 9, 50, 10)
    """
    return datetime.datetime(*parsedate(string)[:6])


def datetime_to_http_date(the_datetime):
    """
    >>> datetime_to_http_date(datetime.datetime(2013, 12, 26, 9, 50, 10))
    'Thu, 26 Dec 2013 09:50:10 GMT'

    # Verify inverses
    >>> x = 'Thu, 26 Dec 2013 09:50:10 GMT'
    >>> datetime_to_http_date(http_date_to_datetime(x)) == x
    True
    """
    timeval = calendar.timegm(the_datetime.utctimetuple())
    return formatdate(timeval=timeval,
                      localtime=False,
                      usegmt=True)


def datetime_to_iso_date(the_datetime):
    """
    >>> datetime_to_iso_date(datetime.datetime(2013, 12, 26, 10, 11, 12))
    '2013-12-26T10:11:12Z'

    >>> datetime_to_iso_date( datetime.datetime(2013, 12, 26, 10, 11, 12))
    '2013-12-26T10:11:12Z'
    """

    return the_datetime.strftime(ISO_DT)


def datetime_to_timestamp(the_datetime):
    """
    >>> datetime_to_timestamp(datetime.datetime(2013, 12, 26, 10, 11, 12))
    '20131226101112'
    """

    return the_datetime.strftime(TIMESTAMP_14)


def timestamp_now():
    """
    >>> len(timestamp_now())
    14
    """
    return datetime_to_timestamp(datetime.datetime.utcnow())


def timestamp20_now():
    """
    Create 20-digit timestamp, useful to timestamping temp files

    >>> n = timestamp20_now()
    >>> timestamp20_now() >= n
    True

    >>> len(n)
    20

    """
    now = datetime.datetime.utcnow()
    return now.strftime('%Y%m%d%H%M%S%f')


def iso_date_to_timestamp(string):
    """
    >>> iso_date_to_timestamp('2013-12-26T10:11:12Z')
    '20131226101112'

    >>> iso_date_to_timestamp('2013-12-26T10:11:12')
    '20131226101112'
     """

    return datetime_to_timestamp(iso_date_to_datetime(string))


def http_date_to_timestamp(string):
    """
    >>> http_date_to_timestamp('Thu, 26 Dec 2013 09:50:00 GMT')
    '20131226095000'

    >>> http_date_to_timestamp('Sun, 26 Jan 2014 20:08:04 GMT')
    '20140126200804'
    """
    return datetime_to_timestamp(http_date_to_datetime(string))


# pad to certain length (default 6)
def pad_timestamp(string, pad_str=PAD_6_UP):
    """
    >>> pad_timestamp('20')
    '209912'

    >>> pad_timestamp('2014')
    '201412'

    >>> pad_timestamp('20141011')
    '20141011'

    >>> pad_timestamp('201410110010')
    '201410110010'
     """

    str_len = len(string)
    pad_len = len(pad_str)

    if str_len < pad_len:
        string = string + pad_str[str_len:]

    return string


def timestamp_to_datetime(string):
    """
    # >14-digit -- rest ignored
    >>> timestamp_to_datetime('2014122609501011')
    datetime.datetime(2014, 12, 26, 9, 50, 10)

    # 14-digit
    >>> timestamp_to_datetime('20141226095010')
    datetime.datetime(2014, 12, 26, 9, 50, 10)

    # 13-digit padding
    >>> timestamp_to_datetime('2014122609501')
    datetime.datetime(2014, 12, 26, 9, 50, 59)

    # 12-digit padding
    >>> timestamp_to_datetime('201412260950')
    datetime.datetime(2014, 12, 26, 9, 50, 59)

    # 11-digit padding
    >>> timestamp_to_datetime('20141226095')
    datetime.datetime(2014, 12, 26, 9, 59, 59)

    # 10-digit padding
    >>> timestamp_to_datetime('2014122609')
    datetime.datetime(2014, 12, 26, 9, 59, 59)

    # 9-digit padding
    >>> timestamp_to_datetime('201412260')
    datetime.datetime(2014, 12, 26, 23, 59, 59)

    # 8-digit padding
    >>> timestamp_to_datetime('20141226')
    datetime.datetime(2014, 12, 26, 23, 59, 59)

    # 7-digit padding
    >>> timestamp_to_datetime('2014122')
    datetime.datetime(2014, 12, 31, 23, 59, 59)

    # 6-digit padding
    >>> timestamp_to_datetime('201410')
    datetime.datetime(2014, 10, 31, 23, 59, 59)

    # 5-digit padding
    >>> timestamp_to_datetime('20141')
    datetime.datetime(2014, 12, 31, 23, 59, 59)

    # 4-digit padding
    >>> timestamp_to_datetime('2014')
    datetime.datetime(2014, 12, 31, 23, 59, 59)

    # 3-digit padding
    >>> timestamp_to_datetime('201')
    datetime.datetime(2019, 12, 31, 23, 59, 59)

    # 2-digit padding
    >>> timestamp_to_datetime('20')
    datetime.datetime(2099, 12, 31, 23, 59, 59)

    # 1-digit padding
    >>> timestamp_to_datetime('2')
    datetime.datetime(2999, 12, 31, 23, 59, 59)

    # 1-digit out-of-range padding
    >>> timestamp_to_datetime('3')
    datetime.datetime(2999, 12, 31, 23, 59, 59)

    # 0-digit padding
    >>> timestamp_to_datetime('')
    datetime.datetime(2999, 12, 31, 23, 59, 59)

    # bad month
    >>> timestamp_to_datetime('20131709005601')
    datetime.datetime(2013, 12, 9, 0, 56, 1)

    # all out of range except minutes
    >>> timestamp_to_datetime('40001965252477')
    datetime.datetime(2999, 12, 31, 23, 24, 59)

    # not a number!
    >>> timestamp_to_datetime('2010abc')
    datetime.datetime(2010, 12, 31, 23, 59, 59)

    """

    # pad to 6 digits
    string = pad_timestamp(string, PAD_6_UP)

    def clamp(val, min_, max_):
        try:
            val = int(val)
            val = max(min_, min(val, max_))
            return val
        except:
            return max_

    def extract(string, start, end, min_, max_):
        if len(string) >= end:
            return clamp(string[start:end], min_, max_)
        else:
            return max_

    # now parse, clamp to boundary
    year = extract(string, 0, 4, 1900, 2999)
    month = extract(string, 4, 6, 1, 12)
    day = extract(string, 6, 8, 1, calendar.monthrange(year, month)[1])
    hour = extract(string, 8, 10, 0, 23)
    minute = extract(string, 10, 12, 0, 59)
    second = extract(string, 12, 14, 0, 59)

    return datetime.datetime(year=year,
                             month=month,
                             day=day,
                             hour=hour,
                             minute=minute,
                             second=second)

    # return time.strptime(pad_timestamp(string), TIMESTAMP_14)


def timestamp_to_sec(string):
    """
    >>> timestamp_to_sec('20131226095010')
    1388051410

    # rounds to end of 2014
    >>> timestamp_to_sec('2014')
    1420070399
    """

    return calendar.timegm(timestamp_to_datetime(string).utctimetuple())


def sec_to_timestamp(secs):
    """
    >>> sec_to_timestamp(1388051410)
    '20131226095010'

    >>> sec_to_timestamp(1420070399)
    '20141231235959'
    """

    return datetime_to_timestamp(datetime.datetime.utcfromtimestamp(secs))


def timestamp_to_http_date(string):
    """
    >>> timestamp_to_http_date('20131226095000')
    'Thu, 26 Dec 2013 09:50:00 GMT'

    >>> timestamp_to_http_date('20140126200804')
    'Sun, 26 Jan 2014 20:08:04 GMT'
    """
    return datetime_to_http_date(timestamp_to_datetime(string))


# end pywb.utils.timeutils

# begin pywb.utils.statusandheaders
# =================================================================
class StatusAndHeaders(object):
    """
    Representation of parsed http-style status line and headers
    Status Line if first line of request/response
    Headers is a list of (name, value) tuples
    An optional protocol which appears on first line may be specified
    """

    def __init__(self, statusline, headers, protocol='', total_len=0):
        self.statusline = statusline
        self.headers = headers
        self.protocol = protocol
        self.total_len = total_len

    def get_header(self, name):
        """
        return header (name, value)
        if found
        """
        name_lower = name.lower()
        for value in self.headers:
            if value[0].lower() == name_lower:
                return value[1]

    def replace_header(self, name, value):
        """
        replace header with new value or add new header
        return old header value, if any
        """
        name_lower = name.lower()
        for index in range(len(self.headers) - 1, -1, -1):
            curr_name, curr_value = self.headers[index]
            if curr_name.lower() == name_lower:
                self.headers[index] = (curr_name, value)
                return curr_value

        self.headers.append((name, value))
        return None

    def replace_headers(self, header_dict):
        """
        replace all headers in header_dict that already exist
        add any remaining headers
        """
        header_dict = copy(header_dict)

        for index in range(len(self.headers) - 1, -1, -1):
            curr_name, curr_value = self.headers[index]
            name_lower = curr_name.lower()
            if name_lower in header_dict:
                self.headers[index] = (curr_name, header_dict[name_lower])
                del header_dict[name_lower]

        for name, value in iteritems(header_dict):
            self.headers.append((name, value))

    def remove_header(self, name):
        """
        Remove header (case-insensitive)
        return True if header removed, False otherwise
        """
        name_lower = name.lower()
        for index in range(len(self.headers) - 1, -1, -1):
            if self.headers[index][0].lower() == name_lower:
                del self.headers[index]
                return True

        return False

    def get_statuscode(self):
        """
        Return the statuscode part of the status response line
        (Assumes no protocol in the statusline)
        """
        code = self.statusline.split(' ', 1)[0]
        return code

    def validate_statusline(self, valid_statusline):
        """
        Check that the statusline is valid, eg. starts with a numeric
        code. If not, replace with passed in valid_statusline
        """
        code = self.get_statuscode()
        try:
            code = int(code)
            assert (code > 0)
            return True
        except(ValueError, AssertionError):
            self.statusline = valid_statusline
            return False

    def add_range(self, start, part_len, total_len):
        """
        Add range headers indicating that this a partial response
        """
        content_range = 'bytes {0}-{1}/{2}'.format(start,
                                                   start + part_len - 1,
                                                   total_len)

        self.statusline = '206 Partial Content'
        self.replace_header('Content-Range', content_range)
        self.replace_header('Accept-Ranges', 'bytes')
        return self

    def __repr__(self):
        headers_str = pformat(self.headers, indent=2, width=WRAP_WIDTH)
        return "StatusAndHeaders(protocol = '{0}', statusline = '{1}', \
headers = {2})".format(self.protocol, self.statusline, headers_str)

    def __eq__(self, other):
        return (self.statusline == other.statusline and
                self.headers == other.headers and
                self.protocol == other.protocol)

    def __str__(self, exclude_list=None):
        return self.to_str(exclude_list)

    def to_str(self, exclude_list):
        string = self.protocol

        if string and self.statusline:
            string += ' '

        if self.statusline:
            string += self.statusline

        if string:
            string += '\r\n'

        for h in self.headers:
            if exclude_list and h[0].lower() in exclude_list:
                continue

            string += ': '.join(h) + '\r\n'

        return string

    def to_bytes(self, exclude_list=None):
        return self.to_str(exclude_list).encode('iso-8859-1') + b'\r\n'


# =================================================================
def _strip_count(string, total_read):
    length = len(string)
    return string.rstrip(), total_read + length


# =================================================================
class StatusAndHeadersParser(object):
    """
    Parser which consumes a stream support readline() to read
    status and headers and return a StatusAndHeaders object
    """

    def __init__(self, statuslist, verify=True):
        self.statuslist = statuslist
        self.verify = verify

    def parse(self, stream, full_statusline=None):
        """
        parse stream for status line and headers
        return a StatusAndHeaders object

        support continuation headers starting with space or tab
        """

        def readline():
            return to_native_str(stream.readline())

        # status line w newlines intact
        if full_statusline is None:
            full_statusline = readline()
        else:
            full_statusline = to_native_str(full_statusline)

        statusline, total_read = _strip_count(full_statusline, 0)

        headers = []

        # at end of stream
        if total_read == 0:
            raise EOFError()
        elif not statusline:
            return StatusAndHeaders(statusline=statusline,
                                    headers=headers,
                                    protocol='',
                                    total_len=total_read)

        # validate only if verify is set
        if self.verify:
            protocol_status = self.split_prefix(statusline, self.statuslist)

            if not protocol_status:
                msg = 'Expected Status Line starting with {0} - Found: {1}'
                msg = msg.format(self.statuslist, statusline)
                raise StatusAndHeadersParserException(msg, full_statusline)
        else:
            protocol_status = statusline.split(' ', 1)

        line, total_read = _strip_count(readline(), total_read)
        while line:
            result = line.split(':', 1)
            if len(result) == 2:
                name = result[0].rstrip(' \t')
                value = result[1].lstrip()
            else:
                name = result[0]
                value = None

            next_line, total_read = _strip_count(readline(),
                                                 total_read)

            # append continuation lines, if any
            while next_line and next_line.startswith((' ', '\t')):
                if value is not None:
                    value += next_line
                next_line, total_read = _strip_count(readline(),
                                                     total_read)

            if value is not None:
                header = (name, value)
                headers.append(header)

            line = next_line

        if len(protocol_status) > 1:
            statusline = protocol_status[1].strip()
        else:
            statusline = ''

        return StatusAndHeaders(statusline=statusline,
                                headers=headers,
                                protocol=protocol_status[0],
                                total_len=total_read)

    @staticmethod
    def split_prefix(key, prefixs):
        """
        split key string into prefix and remainder
        for first matching prefix from a list
        """
        key_upper = key.upper()
        for prefix in prefixs:
            if key_upper.startswith(prefix):
                plen = len(prefix)
                return (key_upper[:plen], key[plen:])


# =================================================================
class StatusAndHeadersParserException(Exception):
    """
    status + headers parsing exception
    """

    def __init__(self, msg, statusline):
        super(StatusAndHeadersParserException, self).__init__(msg)
        self.statusline = statusline


# end pywb.utils.statusandheaders


# begin pywb.utils.bufferedreader

# =================================================================
def gzip_decompressor():
    """
    Decompressor which can handle decompress gzip stream
    """
    return zlib.decompressobj(16 + zlib.MAX_WBITS)


def deflate_decompressor():
    return zlib.decompressobj()


def deflate_decompressor_alt():
    return zlib.decompressobj(-zlib.MAX_WBITS)


def brotli_decompressor():
    decomp = brotli.Decompressor()
    decomp.unused_data = None
    return decomp


# =================================================================
class BufferedReader(object):
    """
    A wrapping line reader which wraps an existing reader.
    Read operations operate on underlying buffer, which is filled to
    block_size (1024 default)

    If an optional decompress type is specified,
    data is fed through the decompressor when read from the buffer.
    Currently supported decompression: gzip
    If unspecified, default decompression is None

    If decompression is specified, and decompress fails on first try,
    data is assumed to not be compressed and no exception is thrown.

    If a failure occurs after data has been
    partially decompressed, the exception is propagated.

    """

    DECOMPRESSORS = {'gzip': gzip_decompressor,
                     'deflate': deflate_decompressor,
                     'deflate_alt': deflate_decompressor_alt,
                     'br': brotli_decompressor
                     }

    def __init__(self, stream, block_size=1024,
                 decomp_type=None,
                 starting_data=None):
        self.stream = stream
        self.block_size = block_size

        self._init_decomp(decomp_type)

        self.buff = None
        self.starting_data = starting_data
        self.num_read = 0
        self.buff_size = 0

    def set_decomp(self, decomp_type):
        self._init_decomp(decomp_type)

    def _init_decomp(self, decomp_type):
        if decomp_type:
            try:
                self.decomp_type = decomp_type
                self.decompressor = self.DECOMPRESSORS[decomp_type.lower()]()
            except KeyError:
                raise Exception('Decompression type not supported: ' +
                                decomp_type)
        else:
            self.decomp_type = None
            self.decompressor = None

    def _fillbuff(self, block_size=None):
        if not self.empty():
            return

        # can't read past next member
        if self.rem_length() > 0:
            return

        if self.starting_data:
            data = self.starting_data
            self.starting_data = None
        else:
            if not block_size:
                block_size = self.block_size
            data = self.stream.read(block_size)

        self._process_read(data)

    def _process_read(self, data):
        data = self._decompress(data)
        self.buff_size = len(data)
        self.num_read += self.buff_size
        self.buff = BytesIO(data)

    def _decompress(self, data):
        if self.decompressor and data:
            try:
                data = self.decompressor.decompress(data)
            except Exception as e:
                # if first read attempt, assume non-gzipped stream
                if self.num_read == 0:
                    if self.decomp_type == 'deflate':
                        self._init_decomp('deflate_alt')
                        data = self._decompress(data)
                    else:
                        self.decompressor = None
                # otherwise (partly decompressed), something is wrong
                else:
                    print(str(e))
                    return b''
        return data

    def read(self, length=None):
        """
        Fill bytes and read some number of bytes
        (up to length if specified)
        < length bytes may be read if reached the end of input
        or at a buffer boundary. If at a boundary, the subsequent
        call will fill buffer anew.
        """
        if length == 0:
            return b''

        self._fillbuff()
        buff = self.buff.read(length)
        return buff

    def readline(self, length=None):
        """
        Fill buffer and read a full line from the buffer
        (up to specified length, if provided)
        If no newline found at end, try filling buffer again in case
        at buffer boundary.
        """
        if length == 0:
            return b''

        self._fillbuff()
        linebuff = self.buff.readline(length)

        # we may be at a boundary
        while not linebuff.endswith(b'\n'):
            if length:
                length -= len(linebuff)
                if length <= 0:
                    break

            self._fillbuff()

            if self.empty():
                break

            linebuff += self.buff.readline(length)

        return linebuff

    def empty(self):
        return not self.buff or self.buff.tell() >= self.buff_size

    def read_next_member(self):
        if not self.decompressor or not self.decompressor.unused_data:
            return False

        self.starting_data = self.decompressor.unused_data
        self._init_decomp(self.decomp_type)
        return True

    def rem_length(self):
        rem = 0
        if self.buff:
            rem = self.buff_size - self.buff.tell()

        if self.decompressor and self.decompressor.unused_data:
            rem += len(self.decompressor.unused_data)
        return rem

    def close(self):
        if self.stream:
            self.stream.close()
            self.stream = None

    @classmethod
    def get_supported_decompressors(cls):
        return cls.DECOMPRESSORS.keys()


# =================================================================
class DecompressingBufferedReader(BufferedReader):
    """
    A BufferedReader which defaults to gzip decompression,
    (unless different type specified)
    """

    def __init__(self, *args, **kwargs):
        if 'decomp_type' not in kwargs:
            kwargs['decomp_type'] = 'gzip'
        super(DecompressingBufferedReader, self).__init__(*args, **kwargs)


# =================================================================
class ChunkedDataException(Exception):
    def __init__(self, msg, data=b''):
        Exception.__init__(self, msg)
        self.data = data


# =================================================================
class ChunkedDataReader(BufferedReader):
    r"""
    A ChunkedDataReader is a DecompressingBufferedReader
    which also supports de-chunking of the data if it happens
    to be http 'chunk-encoded'.

    If at any point the chunked header is not available, the stream is
    assumed to not be chunked and no more dechunking occurs.
    """

    def __init__(self, stream, raise_exceptions=False, **kwargs):
        super(ChunkedDataReader, self).__init__(stream, **kwargs)
        self.all_chunks_read = False
        self.not_chunked = False

        # if False, we'll use best-guess fallback for parse errors
        self.raise_chunked_data_exceptions = raise_exceptions

    def _fillbuff(self, block_size=None):
        if self.not_chunked:
            return super(ChunkedDataReader, self)._fillbuff(block_size)

        # Loop over chunks until there is some data (not empty())
        # In particular, gzipped data may require multiple chunks to
        # return any decompressed result
        while (self.empty() and
                   not self.all_chunks_read and
                   not self.not_chunked):

            try:
                length_header = self.stream.readline(64)
                self._try_decode(length_header)
            except ChunkedDataException as e:
                if self.raise_chunked_data_exceptions:
                    raise

                # Can't parse the data as chunked.
                # It's possible that non-chunked data is served
                # with a Transfer-Encoding: chunked.
                # Treat this as non-chunk encoded from here on.
                self._process_read(length_header + e.data)
                self.not_chunked = True

                # parse as block as non-chunked
                return super(ChunkedDataReader, self)._fillbuff(block_size)

    def _try_decode(self, length_header):
        # decode length header
        try:
            chunk_size = int(length_header.strip().split(b';')[0], 16)
        except ValueError:
            raise ChunkedDataException(b"Couldn't decode length header " +
                                       length_header)

        if not chunk_size:
            # chunk_size 0 indicates end of file
            self.all_chunks_read = True
            self._process_read(b'')
            return

        data_len = 0
        data = b''

        # read chunk
        while data_len < chunk_size:
            new_data = self.stream.read(chunk_size - data_len)

            # if we unexpectedly run out of data,
            # either raise an exception or just stop reading,
            # assuming file was cut off
            if not new_data:
                if self.raise_chunked_data_exceptions:
                    msg = 'Ran out of data before end of chunk'
                    raise ChunkedDataException(msg, data)
                else:
                    chunk_size = data_len
                    self.all_chunks_read = True

            data += new_data
            data_len = len(data)

        # if we successfully read a block without running out,
        # it should end in \r\n
        if not self.all_chunks_read:
            clrf = self.stream.read(2)
            if clrf != b'\r\n':
                raise ChunkedDataException(b"Chunk terminator not found.",
                                           data)

        # hand to base class for further processing
        self._process_read(data)

    def read(self, length=None):
        """ read bytes from stream, if length specified,
        may read across multiple chunks to get exact length
        """
        buf = super(ChunkedDataReader, self).read(length)
        if not length:
            return buf

        # if length specified, attempt to read exact length
        rem = length - len(buf)
        while rem > 0:
            new_buf = super(ChunkedDataReader, self).read(rem)
            if not new_buf:
                break

            buf += new_buf
            rem -= len(new_buf)

        return buf


# end pywb.utils.bufferedreader

# begin pywb.utils.dsrules

# =================================================================
class RuleSet(object):
    DEFAULT_KEY = ''

    def __init__(self, rule_cls, fieldname, **kwargs):
        """
        A domain specific rules block, inited via config map.
        If config map not specified, it is loaded from default location.

        The rules are represented as a map by domain.
        Each rules configuration will load is own field type
        from the list and given a specified rule_cls.
        """

        self.rules = []

        default_rule_config = kwargs.get('default_rule_config')

        ds_rules_file = kwargs.get('ds_rules_file')

        if not ds_rules_file:
            ds_rules_file = DEFAULT_RULES_FILE

        config = load_yaml_config(ds_rules_file)

        # load rules dict or init to empty
        rulesmap = config.get('rules') if config else {}

        def_key_found = False

        # iterate over master rules file
        for value in rulesmap:
            url_prefix = value.get('url_prefix')
            rules_def = value.get(fieldname)
            if not rules_def:
                continue

            if url_prefix == self.DEFAULT_KEY:
                def_key_found = True

            self.rules.append(rule_cls(url_prefix, rules_def))

        # if default_rule_config provided, always init a default ruleset
        if not def_key_found and default_rule_config is not None:
            self.rules.append(rule_cls(self.DEFAULT_KEY, default_rule_config))

    def iter_matching(self, urlkey):
        """
        Iterate over all matching rules for given urlkey
        """
        for rule in self.rules:
            if rule.applies(urlkey):
                yield rule

    def get_first_match(self, urlkey):
        for rule in self.rules:
            if rule.applies(urlkey):
                return rule


# =================================================================
class BaseRule(object):
    """
    Base rule class -- subclassed to handle specific
    rules for given url_prefix key
    """

    def __init__(self, url_prefix, rules):
        self.url_prefix = url_prefix
        if not isinstance(self.url_prefix, list):
            self.url_prefix = [self.url_prefix]

    def applies(self, urlkey):
        return any(urlkey.startswith(x) for x in self.url_prefix)


# end pywb.utils.dsrules


# begin pywb.utils.binsearch
if six.PY3:
    def cmp(a, b):
        return (a > b) - (a < b)


# =================================================================
def binsearch_offset(reader, key, compare_func=cmp, block_size=8192):
    """
    Find offset of the line which matches a given 'key' using binary search
    If key is not found, the offset is of the line after the key

    File is subdivided into block_size (default 8192) sized blocks
    Optional compare_func may be specified
    """
    min_ = 0

    reader.seek(0, 2)
    max_ = int(reader.tell() / block_size)

    while max_ - min_ > 1:
        mid = int(min_ + ((max_ - min_) / 2))
        reader.seek(mid * block_size)

        if mid > 0:
            reader.readline()  # skip partial line

        line = reader.readline()

        if compare_func(key, line) > 0:
            min_ = mid
        else:
            max_ = mid

    return min_ * block_size


# =================================================================
def binsearch(reader, key, compare_func=cmp, block_size=8192):
    """
    Perform a binary search for a specified key to within a 'block_size'
    (default 8192) granularity, and return first full line found.
    """

    min_ = binsearch_offset(reader, key, compare_func, block_size)

    reader.seek(min_)

    if min_ > 0:
        reader.readline()  # skip partial line

    def gen_iter(line):
        while line:
            yield line.rstrip()
            line = reader.readline()

    return gen_iter(reader.readline())


# =================================================================
def linearsearch(iter_, key, prev_size=0, compare_func=cmp):
    """
    Perform a linear search over iterator until
    current_line >= key

    optionally also tracking upto N previous lines, which are
    returned before the first matched line.

    if end of stream is reached before a match is found,
    nothing is returned (prev lines discarded also)
    """

    prev_deque = deque(maxlen=prev_size + 1)

    matched = False

    for line in iter_:
        prev_deque.append(line)
        if compare_func(line, key) >= 0:
            matched = True
            break

    # no matches, so return empty iterator
    if not matched:
        return iter([])

    return itertools.chain(prev_deque, iter_)


# =================================================================
def search(reader, key, prev_size=0, compare_func=cmp, block_size=8192):
    """
    Perform a binary search for a specified key to within a 'block_size'
    (default 8192) sized block followed by linear search
    within the block to find first matching line.

    When performin_g linear search, keep track of up to N previous lines before
    first matching line.
    """
    iter_ = binsearch(reader, key, compare_func, block_size)
    iter_ = linearsearch(iter_,
                         key, prev_size=prev_size,
                         compare_func=compare_func)
    return iter_


# =================================================================
def iter_range(reader, start, end, prev_size=0):
    """
    Creates an iterator which iterates over lines where
    start <= line < end (end exclusive)
    """

    iter_ = search(reader, start, prev_size=prev_size)

    end_iter = itertools.takewhile(
        lambda line: line < end,
        iter_)

    return end_iter


# =================================================================
def iter_prefix(reader, key):
    """
    Creates an iterator which iterates over lines that start with prefix
    'key' in a sorted text file.
    """

    return itertools.takewhile(
        lambda line: line.startswith(key),
        search(reader, key))


# =================================================================
def iter_exact(reader, key, token=b' '):
    """
    Create an iterator which iterates over lines where the first field matches
    the 'key', equivalent to token + sep prefix.
    Default field termin_ator/seperator is ' '
    """

    return iter_prefix(reader, key + token)


# end pywb.utils.binsearch


# begin pywb.utils.canonicalize
# =================================================================
class UrlCanonicalizer(object):
    def __init__(self, surt_ordered=True):
        self.surt_ordered = surt_ordered

    def __call__(self, url):
        return canonicalize(url, self.surt_ordered)


# =================================================================
class UrlCanonicalizeException(BadRequestException):
    pass


# =================================================================
def canonicalize(url, surt_ordered=True):
    """
    Canonicalize url and convert to surt
    If not in surt ordered mode, convert back to url form
    as surt conversion is currently part of canonicalization

    >>> canonicalize('http://example.com/path/file.html', surt_ordered=True)
    'com,example)/path/file.html'

    >>> canonicalize('http://example.com/path/file.html', surt_ordered=False)
    'example.com/path/file.html'

    >>> canonicalize('urn:some:id')
    'urn:some:id'
    """
    try:
        key = surt.surt(url)
    except Exception as e:  # pragma: no cover
        # doesn't happen with surt from 0.3b
        # urn is already canonical, so just use as-is
        if url.startswith('urn:'):
            return url

        raise UrlCanonicalizeException('Invalid Url: ' + url)

    # if not surt, unsurt the surt to get canonicalized non-surt url
    if not surt_ordered:
        key = unsurt(key)

    return key


# =================================================================
def unsurt(surt):
    """
    # Simple surt
    >>> unsurt('com,example)/')
    'example.com/'

    # Broken surt
    >>> unsurt('com,example)')
    'com,example)'

    # Long surt
    >>> unsurt('suffix,domain,sub,subsub,another,subdomain)/path/file/index.html?a=b?c=)/')
    'subdomain.another.subsub.sub.domain.suffix/path/file/index.html?a=b?c=)/'
    """

    try:
        index = surt.index(')/')
        parts = surt[0:index].split(',')
        parts.reverse()
        host = '.'.join(parts)
        host += surt[index + 1:]
        return host

    except ValueError:
        # May not be a valid surt
        return surt


# =================================================================
def calc_search_range(url, match_type, surt_ordered=True, url_canon=None):
    """
    Canonicalize a url (either with custom canonicalizer or
    standard canonicalizer with or without surt)

    Then, compute a start and end search url search range
    for a given match type.

    Support match types:
    * exact
    * prefix
    * host
    * domain (only available when for surt ordering)

    Examples below:

    # surt ranges
    >>> calc_search_range('http://example.com/path/file.html', 'exact')
    ('com,example)/path/file.html', 'com,example)/path/file.html!')

    >>> calc_search_range('http://example.com/path/file.html', 'prefix')
    ('com,example)/path/file.html', 'com,example)/path/file.htmm')

    >>> calc_search_range('http://example.com/path/file.html', 'host')
    ('com,example)/', 'com,example*')

    >>> calc_search_range('http://example.com/path/file.html', 'domain')
    ('com,example)/', 'com,example-')

    special case for tld domain range
    >>> calc_search_range('com', 'domain')
    ('com,', 'com-')

    # non-surt ranges
    >>> calc_search_range('http://example.com/path/file.html', 'exact', False)
    ('example.com/path/file.html', 'example.com/path/file.html!')

    >>> calc_search_range('http://example.com/path/file.html', 'prefix', False)
    ('example.com/path/file.html', 'example.com/path/file.htmm')

    >>> calc_search_range('http://example.com/path/file.html', 'host', False)
    ('example.com/', 'example.com0')

    # errors: domain range not supported
    >>> calc_search_range('http://example.com/path/file.html', 'domain', False)  # doctest: +IGNORE_EXCEPTION_DETAIL
    Traceback (most recent call last):
    UrlCanonicalizeException: matchType=domain unsupported for non-surt

    >>> calc_search_range('http://example.com/path/file.html', 'blah', False)   # doctest: +IGNORE_EXCEPTION_DETAIL
    Traceback (most recent call last):
    UrlCanonicalizeException: Invalid match_type: blah

    """

    def inc_last_char(x):
        return x[0:-1] + chr(ord(x[-1]) + 1)

    if not url_canon:
        # make new canon
        url_canon = UrlCanonicalizer(surt_ordered)
    else:
        # ensure surt order matches url_canon
        surt_ordered = url_canon.surt_ordered

    start_key = url_canon(url)

    if match_type == 'exact':
        end_key = start_key + '!'

    elif match_type == 'prefix':
        # add trailing slash if url has it
        if url.endswith('/') and not start_key.endswith('/'):
            start_key += '/'

        end_key = inc_last_char(start_key)

    elif match_type == 'host':
        if surt_ordered:
            host = start_key.split(')/')[0]

            start_key = host + ')/'
            end_key = host + '*'
        else:
            host = urlparse.urlsplit(url).netloc

            start_key = host + '/'
            end_key = host + '0'

    elif match_type == 'domain':
        if not surt_ordered:
            msg = 'matchType=domain unsupported for non-surt'
            raise UrlCanonicalizeException(msg)

        host = start_key.split(')/')[0]

        # if tld, use com, as start_key
        # otherwise, stick with com,example)/
        if ',' not in host:
            start_key = host + ','
        else:
            start_key = host + ')/'

        end_key = host + '-'
    else:
        raise UrlCanonicalizeException('Invalid match_type: ' + match_type)

    return (start_key, end_key)


# end pywb.utils.canonicalize


# begin pywb.framework.wbrequestresponse
# =================================================================
class WbRequest(object):
    """
    Represents the main pywb request object.

    Contains various info from wsgi env, add additional info
    about the request, such as coll, relative prefix,
    host prefix, absolute prefix.

    If a wburl and url rewriter classes are specified, the class
    also contains the url rewriter.

    """

    @staticmethod
    def make_host_prefix(env):
        try:
            host = env.get('HTTP_HOST')
            if not host:
                host = env['SERVER_NAME'] + ':' + env['SERVER_PORT']

            return env.get('wsgi.url_scheme', 'http') + '://' + host
        except KeyError:
            return ''

    def __init__(self, env,
                 request_uri=None,
                 rel_prefix='',
                 wb_url_str='/',
                 coll='',
                 host_prefix='',
                 use_abs_prefix=False,
                 wburl_class=None,
                 urlrewriter_class=None,
                 is_proxy=False,
                 cookie_scope=None,
                 rewrite_opts={},
                 user_metadata={},
                 ):

        self.env = env

        if request_uri:
            self.request_uri = request_uri
        else:
            self.request_uri = env.get('REL_REQUEST_URI')

        self.method = self.env.get('REQUEST_METHOD')

        self.coll = coll

        self.final_mod = ''

        if not host_prefix:
            host_prefix = self.make_host_prefix(env)

        self.host_prefix = host_prefix
        self.rel_prefix = rel_prefix

        if use_abs_prefix:
            self.wb_prefix = host_prefix + rel_prefix
        else:
            self.wb_prefix = rel_prefix

        if not wb_url_str:
            wb_url_str = '/'

        self.wb_url_str = wb_url_str

        # wb_url present and not root page
        if wb_url_str != '/' and wburl_class:
            self.wb_url = wburl_class(wb_url_str)
            self.urlrewriter = urlrewriter_class(self.wb_url,
                                                 self.wb_prefix,
                                                 host_prefix + rel_prefix,
                                                 rel_prefix,
                                                 env.get('SCRIPT_NAME', '/'),
                                                 cookie_scope,
                                                 rewrite_opts)

            self.urlrewriter.deprefix_url()
        # no wb_url, just store blank wb_url
        else:
            self.wb_url = None
            self.urlrewriter = None

        self.referrer = env.get('HTTP_REFERER')

        self.options = dict()
        self.options['is_ajax'] = self._is_ajax()
        self.options['is_proxy'] = is_proxy or env.get('pywb_proxy_magic')

        self.query_filter = []
        self.custom_params = {}
        self.user_metadata = user_metadata
        self.rewrite_opts = rewrite_opts

        # PERF
        env['X_PERF'] = {}

        if env.get('HTTP_X_PYWB_NOREDIRECT'):
            self.custom_params['noredir'] = True

        self._parse_extra()

    def _is_ajax(self):
        value = self.env.get('HTTP_X_REQUESTED_WITH')
        value = value or self.env.get('HTTP_X_PYWB_REQUESTED_WITH')
        if value and value.lower() == 'xmlhttprequest':
            return True

        return False

    RANGE_ARG_RX = re.compile('.*.googlevideo.com/videoplayback.*([&?]range=(\d+)-(\d+))')

    RANGE_HEADER = re.compile('bytes=(\d+)-(\d+)?')

    def extract_range(self):
        url = self.wb_url.url
        use_206 = False
        start = None
        end = None

        range_h = self.env.get('HTTP_RANGE')

        if range_h:
            m = self.RANGE_HEADER.match(range_h)
            if m:
                start = m.group(1)
                end = m.group(2)
                use_206 = True

        else:
            m = self.RANGE_ARG_RX.match(url)
            if m:
                start = m.group(2)
                end = m.group(3)
                url = url[:m.start(1)] + url[m.end(1):]
                use_206 = False

        if not start:
            return None

        start = int(start)
        self.custom_params['noredir'] = True

        if end:
            end = int(end)
        else:
            end = ''

        result = (url, start, end, use_206)
        return result

    def __repr__(self):
        varlist = vars(self)
        varstr = pprint.pformat(varlist)
        return varstr

    def _parse_extra(self):
        pass

    def extract_referrer_wburl_str(self):
        if not self.referrer:
            return None

        if not self.referrer.startswith(self.host_prefix + self.rel_prefix):
            return None

        wburl_str = self.referrer[len(self.host_prefix + self.rel_prefix):]
        return wburl_str

    def normalize_post_query(self):
        if self.method != 'POST':
            return

        if not self.wb_url:
            return

        mime = self.env.get('CONTENT_TYPE', '')
        length = self.env.get('CONTENT_LENGTH')
        stream = self.env['wsgi.input']

        buffered_stream = BytesIO()

        post_query = extract_post_query('POST', mime, length, stream,
                                        buffered_stream=buffered_stream,
                                        environ=self.env)

        if post_query:
            self.env['wsgi.input'] = buffered_stream
            self.wb_url.url = append_post_query(self.wb_url.url, post_query)


# =================================================================
class WbResponse(object):
    """
    Represnts a pywb wsgi response object.

    Holds a status_headers object and a response iter, to be
    returned to wsgi container.
    """

    def __init__(self, status_headers, value=[], **kwargs):
        self.status_headers = status_headers
        self.body = value
        self._init_derived(kwargs)

    def _init_derived(self, params):
        pass

    @staticmethod
    def text_stream(stream, content_type='text/plain; charset=utf-8', status='200 OK'):
        def encode(stream):
            for obj in stream:
                yield obj.encode('utf-8')

        if 'charset' not in content_type:
            content_type += '; charset=utf-8'

        return WbResponse.bin_stream(encode(stream), content_type, status)

    @staticmethod
    def bin_stream(stream, content_type, status='200 OK',
                   headers=None):
        def_headers = [('Content-Type', content_type)]
        if headers:
            def_headers += headers

        status_headers = StatusAndHeaders(status, def_headers)

        return WbResponse(status_headers, value=stream)

    @staticmethod
    def text_response(text, status='200 OK', content_type='text/plain; charset=utf-8'):
        status_headers = StatusAndHeaders(status,
                                          [('Content-Type', content_type),
                                           ('Content-Length', str(len(text)))])

        return WbResponse(status_headers, value=[text.encode('utf-8')])

    @staticmethod
    def redir_response(location, status='302 Redirect', headers=None):
        redir_headers = [('Location', location), ('Content-Length', '0')]
        if headers:
            redir_headers += headers

        return WbResponse(StatusAndHeaders(status, redir_headers))

    def __call__(self, env, start_response):
        start_response(self.status_headers.statusline,
                       self.status_headers.headers)

        if env['REQUEST_METHOD'] == 'HEAD':
            if hasattr(self.body, 'close'):
                self.body.close()
            return []

        return self.body

    def add_range(self, *args):
        self.status_headers.add_range(*args)
        return self

    def __repr__(self):
        return str(vars(self))


# end pywb.framework.wbrequestresponse


# begin pywb.rewrite.wburl
# =================================================================
class BaseWbUrl(object):
    QUERY = 'query'
    URL_QUERY = 'url_query'
    REPLAY = 'replay'
    LATEST_REPLAY = 'latest_replay'

    def __init__(self, url='', mod='',
                 timestamp='', end_timestamp='', type=None):
        self.url = url
        self.timestamp = timestamp
        self.end_timestamp = end_timestamp
        self.mod = mod
        self.type = type

    def is_replay(self):
        return self.is_replay_type(self.type)

    def is_latest_replay(self):
        return (self.type == BaseWbUrl.LATEST_REPLAY)

    def is_query(self):
        return self.is_query_type(self.type)

    def is_url_query(self):
        return (self.type == BaseWbUrl.URL_QUERY)

    @staticmethod
    def is_replay_type(type_):
        return (type_ == BaseWbUrl.REPLAY or
                type_ == BaseWbUrl.LATEST_REPLAY)

    @staticmethod
    def is_query_type(type_):
        return (type_ == BaseWbUrl.QUERY or
                type_ == BaseWbUrl.URL_QUERY)


# =================================================================
class WbUrl(BaseWbUrl):
    # Regexs
    # ======================
    QUERY_REGEX = re.compile('^(?:([\w\-:]+)/)?(\d*)[*-](\d*)/?(.+)$')
    REPLAY_REGEX = re.compile('^(\d*)([a-z]+_)?/{1,3}(.+)$')
    # LATEST_REPLAY_REGEX = re.compile('^\w_)')

    DEFAULT_SCHEME = 'http://'

    FIRST_PATH = re.compile('(?<![:/])[/?](?![/])')

    @staticmethod
    def percent_encode_host(url):
        """ Convert the host of uri formatted with to_uri()
        to have a %-encoded host instead of punycode host
        The rest of url should be unchanged
        """

        # only continue if punycode encoded
        if 'xn--' not in url:
            return url

        parts = urlsplit(url)
        domain = parts.netloc.encode('utf-8')
        try:
            domain = domain.decode('idna')
            if six.PY2:
                domain = domain.encode('utf-8', 'ignore')
        except:
            # likely already encoded, so use as is
            pass

        domain = quote(domain)  # , safe=r':\/')

        return urlunsplit((parts[0], domain, parts[2], parts[3], parts[4]))

    @staticmethod
    def to_uri(url):
        """ Converts a url to an ascii %-encoded form
        where:
        - scheme is ascii,
        - host is punycode,
        - and remainder is %-encoded
        Not using urlsplit to also decode partially encoded
        scheme urls
        """
        parts = WbUrl.FIRST_PATH.split(url, 1)

        sep = url[len(parts[0])] if len(parts) > 1 else None

        scheme_dom = unquote_plus(parts[0])

        if six.PY2 and isinstance(scheme_dom, six.binary_type):
            if scheme_dom == parts[0]:
                return url

            scheme_dom = scheme_dom.decode('utf-8', 'ignore')

        scheme_dom = scheme_dom.rsplit('/', 1)
        domain = scheme_dom[-1]

        try:
            domain = to_native_str(domain.encode('idna'), 'utf-8')
        except UnicodeError:
            # the url is invalid and this is probably not a domain
            pass

        if len(scheme_dom) > 1:
            url = to_native_str(scheme_dom[0], 'utf-8') + '/' + domain
        else:
            url = domain

        if len(parts) > 1:
            url += sep

            rest = parts[1]
            try:
                rest.encode('ascii')
            except UnicodeEncodeError:
                rest = quote(to_native_str(rest, 'utf-8'))

            url += rest

        return url

    # ======================

    def __init__(self, orig_url):
        super(WbUrl, self).__init__()

        if six.PY2 and isinstance(orig_url, six.text_type):
            orig_url = orig_url.encode('utf-8')
            orig_url = quote(orig_url)

        self._original_url = orig_url

        if not self._init_query(orig_url):
            if not self._init_replay(orig_url):
                raise Exception('Invalid WbUrl: ', orig_url)

        new_uri = WbUrl.to_uri(self.url)

        self._do_percent_encode = True

        self.url = new_uri

        if self.url.startswith('urn:'):
            return

        # protocol agnostic url -> http://
        # no protocol -> http://
        inx = self.url.find(':/')
        # if inx < 0:
        # check for other partially encoded variants
        #    m = self.PARTIAL_ENC_RX.match(self.url)
        #    if m:
        #        len_ = len(m.group(0))
        #        self.url = (urllib.unquote_plus(self.url[:len_]) +
        #                    self.url[len_:])
        #        inx = self.url.find(':/')

        if inx < 0:
            self.url = self.DEFAULT_SCHEME + self.url
        else:
            inx += 2
            if inx < len(self.url) and self.url[inx] != '/':
                self.url = self.url[:inx] + '/' + self.url[inx:]

    # Match query regex
    # ======================
    def _init_query(self, url):
        query = self.QUERY_REGEX.match(url)
        if not query:
            return None

        res = query.groups('')

        self.mod = res[0]
        self.timestamp = res[1]
        self.end_timestamp = res[2]
        self.url = res[3]
        if self.url.endswith('*'):
            self.type = self.URL_QUERY
            self.url = self.url[:-1]
        else:
            self.type = self.QUERY
        return True

    # Match replay regex
    # ======================
    def _init_replay(self, url):
        replay = self.REPLAY_REGEX.match(url)
        if not replay:
            if not url:
                return None

            self.timestamp = ''
            self.mod = ''
            self.url = url
            self.type = self.LATEST_REPLAY
            return True

        res = replay.groups('')

        self.timestamp = res[0]
        self.mod = res[1]
        self.url = res[2]

        if self.timestamp:
            self.type = self.REPLAY
        else:
            self.type = self.LATEST_REPLAY

        return True

    def set_replay_timestamp(self, timestamp):
        self.timestamp = timestamp
        self.type = self.REPLAY

    def deprefix_url(self, prefix):
        rex_query = '=' + re.escape(prefix) + '([0-9])*([\w]{2}_)?/?'
        self.url = re.sub(rex_query, '=', self.url)

        rex_query = '=(' + quote_plus(prefix) + '.*?)((?:https?%3A)?%2F%2F[^&]+)'
        self.url = re.sub(rex_query, '=\\2', self.url)

        return self.url

    def get_url(self, url=None):
        if url is not None:
            url = WbUrl.to_uri(url)
        else:
            url = self.url

        if self._do_percent_encode:
            url = WbUrl.percent_encode_host(url)

        return url

    # Str Representation
    # ====================
    def to_str(self, **overrides):
        type_ = overrides.get('type', self.type)
        mod = overrides.get('mod', self.mod)
        timestamp = overrides.get('timestamp', self.timestamp)
        end_timestamp = overrides.get('end_timestamp', self.end_timestamp)

        url = self.get_url(overrides.get('url', self.url))

        return self.to_wburl_str(url=url,
                                 type=type_,
                                 mod=mod,
                                 timestamp=timestamp,
                                 end_timestamp=end_timestamp)

    @staticmethod
    def to_wburl_str(url, type=BaseWbUrl.LATEST_REPLAY,
                     mod='', timestamp='', end_timestamp=''):

        if WbUrl.is_query_type(type):
            tsmod = ''
            if mod:
                tsmod += mod + "/"

            tsmod += timestamp
            tsmod += '*'
            tsmod += end_timestamp

            tsmod += "/" + url
            if type == BaseWbUrl.URL_QUERY:
                tsmod += "*"
            return tsmod
        else:
            tsmod = timestamp + mod
            if len(tsmod) > 0:
                return tsmod + "/" + url
            else:
                return url

    @property
    def is_embed(self):
        return (self.mod and
                self.mod not in ('id_', 'mp_', 'tf_', 'bn_'))

    @property
    def is_banner_only(self):
        return (self.mod == 'bn_')

    @property
    def is_url_rewrite_only(self):
        return (self.mod == 'uo_')

    @property
    def is_identity(self):
        return (self.mod == 'id_')

    def __str__(self):
        return self.to_str()

    def __repr__(self):
        return str((self.type, self.timestamp, self.mod, self.url, str(self)))


# end pywb.rewrite.wburl

# begin pywb.warc.recordloader
# =================================================================
ArcWarcRecord = collections.namedtuple('ArcWarcRecord',
                                       'format, rec_type, rec_headers, ' +
                                       'stream, status_headers, ' +
                                       'content_type, length')


# =================================================================
class ArchiveLoadFailed(WbException):
    def __init__(self, reason, filename=''):
        if filename:
            msg = filename + ': ' + str(reason)
        else:
            msg = str(reason)

        super(ArchiveLoadFailed, self).__init__(msg)

    def status(self):
        return '503 Service Unavailable'


# =================================================================
class ArcWarcRecordLoader(object):
    # Standard ARC v1.0 headers
    # TODO: support ARC v2.0 also?
    ARC_HEADERS = ["uri", "ip-address", "archive-date",
                   "content-type", "length"]

    WARC_TYPES = ['WARC/1.0', 'WARC/0.17', 'WARC/0.18']

    HTTP_TYPES = ['HTTP/1.0', 'HTTP/1.1']

    HTTP_VERBS = ['GET', 'HEAD', 'POST', 'PUT', 'DELETE', 'TRACE',
                  'OPTIONS', 'CONNECT', 'PATCH']

    NON_HTTP_RECORDS = ('warcinfo', 'arc_header', 'metadata', 'resource')

    NON_HTTP_SCHEMES = ('dns:', 'whois:', 'ntp:')
    HTTP_SCHEMES = ('http:', 'https:')

    def __init__(self, loader=None, cookie_maker=None, block_size=8192,
                 verify_http=True):
        if not loader:
            loader = BlockLoader(cookie_maker=cookie_maker)

        self.loader = loader
        self.block_size = block_size

        self.arc_parser = ARCHeadersParser(self.ARC_HEADERS)

        self.warc_parser = StatusAndHeadersParser(self.WARC_TYPES)
        self.http_parser = StatusAndHeadersParser(self.HTTP_TYPES, verify_http)

        self.http_req_parser = StatusAndHeadersParser(self.HTTP_VERBS, verify_http)

    def load(self, url, offset, length, no_record_parse=False):
        """ Load a single record from given url at offset with length
        and parse as either warc or arc record
        """
        try:
            length = int(length)
        except:
            length = -1

        stream = self.loader.load(url, int(offset), length)
        decomp_type = 'gzip'

        # Create decompressing stream
        stream = DecompressingBufferedReader(stream=stream,
                                             decomp_type=decomp_type,
                                             block_size=self.block_size)

        return self.parse_record_stream(stream, no_record_parse=no_record_parse)

    def parse_record_stream(self, stream,
                            statusline=None,
                            known_format=None,
                            no_record_parse=False):
        """ Parse file-like stream and return an ArcWarcRecord
        encapsulating the record headers, http headers (if any),
        and a stream limited to the remainder of the record.

        Pass statusline and known_format to detect_type_loader_headers()
        to faciliate parsing.
        """
        (the_format, rec_headers) = (self.
                                     _detect_type_load_headers(stream,
                                                               statusline,
                                                               known_format))

        if the_format == 'arc':
            uri = rec_headers.get_header('uri')
            length = rec_headers.get_header('length')
            content_type = rec_headers.get_header('content-type')
            sub_len = rec_headers.total_len
            if uri and uri.startswith('filedesc://'):
                rec_type = 'arc_header'
            else:
                rec_type = 'response'

        elif the_format == 'warc':
            rec_type = rec_headers.get_header('WARC-Type')
            uri = rec_headers.get_header('WARC-Target-URI')
            length = rec_headers.get_header('Content-Length')
            content_type = rec_headers.get_header('Content-Type')
            sub_len = 0

        is_err = False

        try:
            if length is not None:
                length = int(length) - sub_len
                if length < 0:
                    is_err = True

        except (ValueError, TypeError):
            is_err = True

        # err condition
        if is_err:
            length = 0

        # limit stream to the length for all valid records
        if length is not None and length >= 0:
            stream = LimitReader.wrap_stream(stream, length)

        # don't parse the http record at all
        if no_record_parse:
            status_headers = None  # StatusAndHeaders('', [])

        # if empty record (error or otherwise) set status to 204
        elif length == 0:
            if is_err:
                msg = '204 Possible Error'
            else:
                msg = '204 No Content'

            status_headers = StatusAndHeaders(msg, [])

        # response record or non-empty revisit: parse HTTP status and headers!
        elif (rec_type in ('response', 'revisit')
              and uri.startswith(self.HTTP_SCHEMES)):
            status_headers = self.http_parser.parse(stream)

        # request record: parse request
        elif ((rec_type == 'request')
              and uri.startswith(self.HTTP_SCHEMES)):
            status_headers = self.http_req_parser.parse(stream)

        # everything else: create a no-status entry, set content-type
        else:
            content_type_header = [('Content-Type', content_type)]

            if length is not None and length >= 0:
                content_type_header.append(('Content-Length', str(length)))

            status_headers = StatusAndHeaders('200 OK', content_type_header)

        return ArcWarcRecord(the_format, rec_type,
                             rec_headers, stream, status_headers,
                             content_type, length)

    def _detect_type_load_headers(self, stream,
                                  statusline=None, known_format=None):
        """ If known_format is specified ('warc' or 'arc'),
        parse only as that format.

        Otherwise, try parsing record as WARC, then try parsing as ARC.
        if neither one succeeds, we're out of luck.
        """

        if known_format != 'arc':
            # try as warc first
            try:
                rec_headers = self.warc_parser.parse(stream, statusline)
                return 'warc', rec_headers
            except StatusAndHeadersParserException as se:
                if known_format == 'warc':
                    msg = 'Invalid WARC record, first line: '
                    raise ArchiveLoadFailed(msg + str(se.statusline))

                statusline = se.statusline
                pass

        # now try as arc
        try:
            rec_headers = self.arc_parser.parse(stream, statusline)
            return 'arc', rec_headers
        except StatusAndHeadersParserException as se:
            if known_format == 'arc':
                msg = 'Invalid ARC record, first line: '
            else:
                msg = 'Unknown archive format, first line: '
            raise ArchiveLoadFailed(msg + str(se.statusline))


# =================================================================
class ARCHeadersParser(object):
    def __init__(self, headernames):
        self.headernames = headernames

    def parse(self, stream, headerline=None):
        total_read = 0

        def readline():
            return to_native_str(stream.readline())

        # if headerline passed in, use that
        if headerline is None:
            headerline = readline()
        else:
            headerline = to_native_str(headerline)

        header_len = len(headerline)

        if header_len == 0:
            raise EOFError()

        headerline = headerline.rstrip()

        headernames = self.headernames

        # if arc header, consume next two lines
        if headerline.startswith('filedesc://'):
            version = readline()  # skip version
            spec = readline()  # skip header spec, use preset one
            total_read += len(version)
            total_read += len(spec)

        parts = headerline.split(' ')

        if len(parts) != len(headernames):
            msg = 'Wrong # of headers, expected arc headers {0}, Found {1}'
            msg = msg.format(headernames, parts)
            raise StatusAndHeadersParserException(msg, parts)

        headers = []

        for name, value in zip(headernames, parts):
            headers.append((name, value))

        return StatusAndHeaders(statusline='',
                                headers=headers,
                                protocol='ARC/1.0',
                                total_len=total_read)


# end pywb.warc.recordloader

# begin pywb.warc.resolvingloader
# =================================================================
class ResolvingLoader(object):
    MISSING_REVISIT_MSG = 'Original for revisit record could not be loaded'

    def __init__(self, path_resolvers, record_loader=ArcWarcRecordLoader(), no_record_parse=False):
        self.path_resolvers = path_resolvers
        self.record_loader = record_loader
        self.no_record_parse = no_record_parse

    def __call__(self, cdx, failed_files, cdx_loader, *args, **kwargs):
        headers_record, payload_record = self.load_headers_and_payload(cdx, failed_files, cdx_loader)

        # Default handling logic when loading http status/headers

        # special case: set header to payload if old-style revisit
        # with missing header
        if not headers_record:
            headers_record = payload_record
        elif headers_record != payload_record:
            # close remainder of stream as this record only used for
            # (already parsed) headers
            headers_record.stream.close()

            # special case: check if headers record is actually empty
            # (eg empty revisit), then use headers from revisit
            if not headers_record.status_headers.headers:
                headers_record = payload_record

        if not headers_record or not payload_record:
            raise ArchiveLoadFailed('Could not load ' + str(cdx))

        # ensure status line is valid from here
        headers_record.status_headers.validate_statusline('204 No Content')

        return (headers_record.status_headers, payload_record.stream)

    def load_headers_and_payload(self, cdx, failed_files, cdx_loader):
        """
        Resolve headers and payload for a given capture
        In the simple case, headers and payload are in the same record.
        In the case of revisit records, the payload and headers may be in
        different records.

        If the original has already been found, lookup original using
        orig. fields in cdx dict.
        Otherwise, call _load_different_url_payload() to get cdx index
        from a different url to find the original record.
        """
        has_curr = (cdx['filename'] != '-')
        # has_orig = (cdx.get('orig.filename', '-') != '-')
        orig_f = cdx.get('orig.filename')
        has_orig = orig_f and orig_f != '-'

        # load headers record from cdx['filename'] unless it is '-' (rare)
        headers_record = None
        if has_curr:
            headers_record = self._resolve_path_load(cdx, False, failed_files)

        # two index lookups
        # Case 1: if mimetype is still warc/revisit
        if cdx.get('mime') == 'warc/revisit' and headers_record:
            payload_record = self._load_different_url_payload(cdx,
                                                              headers_record,
                                                              failed_files,
                                                              cdx_loader)

        # single lookup cases
        # case 2: non-revisit
        elif (has_curr and not has_orig):
            payload_record = headers_record

        # case 3: identical url revisit, load payload from orig.filename
        elif (has_orig):
            payload_record = self._resolve_path_load(cdx, True, failed_files)

        return headers_record, payload_record

    def _resolve_path_load(self, cdx, is_original, failed_files):
        """
        Load specific record based on filename, offset and length
        fields in the cdx.
        If original=True, use the orig.* fields for the cdx

        Resolve the filename to full path using specified path resolvers

        If failed_files list provided, keep track of failed resolve attempts
        """

        if is_original:
            (filename, offset, length) = (cdx['orig.filename'],
                                          cdx['orig.offset'],
                                          cdx['orig.length'])
        else:
            (filename, offset, length) = (cdx['filename'],
                                          cdx['offset'],
                                          cdx.get('length', '-'))

        # optimization: if same file already failed this request,
        # don't try again
        if failed_files is not None and filename in failed_files:
            raise ArchiveLoadFailed('Skipping Already Failed', filename)

        any_found = False
        last_exc = None
        last_traceback = None
        for resolver in self.path_resolvers:
            possible_paths = resolver(filename, cdx)

            if not possible_paths:
                continue

            if isinstance(possible_paths, six.string_types):
                possible_paths = [possible_paths]

            for path in possible_paths:
                any_found = True
                try:
                    return (self.record_loader.
                            load(path, offset, length,
                                 no_record_parse=self.no_record_parse))

                except Exception as ue:
                    last_exc = ue
                    import sys
                    last_traceback = sys.exc_info()[2]

        # Unsuccessful if reached here
        if failed_files is not None:
            failed_files.append(filename)

        if last_exc:
            # msg = str(last_exc.__class__.__name__)
            msg = str(last_exc)
        else:
            msg = 'Archive File Not Found'

        # raise ArchiveLoadFailed(msg, filename), None, last_traceback
        six.reraise(ArchiveLoadFailed, ArchiveLoadFailed(msg, filename), last_traceback)

    def _load_different_url_payload(self, cdx, headers_record,
                                    failed_files, cdx_loader):
        """
        Handle the case where a duplicate of a capture with same digest
        exists at a different url.

        If a cdx_server is provided, a query is made for matching
        url, timestamp and digest.

        Raise exception if no matches found.
        """

        ref_target_uri = (headers_record.rec_headers.
                          get_header('WARC-Refers-To-Target-URI'))

        target_uri = headers_record.rec_headers.get_header('WARC-Target-URI')

        # if no target uri, no way to find the original
        if not ref_target_uri:
            raise ArchiveLoadFailed(self.MISSING_REVISIT_MSG)

        ref_target_date = (headers_record.rec_headers.
                           get_header('WARC-Refers-To-Date'))

        if not ref_target_date:
            ref_target_date = cdx['timestamp']
        else:
            ref_target_date = iso_date_to_timestamp(ref_target_date)

        digest = cdx.get('digest', '-')

        try:
            orig_cdx_lines = self.load_cdx_for_dupe(ref_target_uri,
                                                    ref_target_date,
                                                    digest,
                                                    cdx_loader)
        except NotFoundException:
            raise ArchiveLoadFailed(self.MISSING_REVISIT_MSG)

        for orig_cdx in orig_cdx_lines:
            try:
                payload_record = self._resolve_path_load(orig_cdx, False,
                                                         failed_files)
                return payload_record

            except ArchiveLoadFailed as e:
                pass

        raise ArchiveLoadFailed(self.MISSING_REVISIT_MSG)

    def load_cdx_for_dupe(self, url, timestamp, digest, cdx_loader):
        """
        If a cdx_server is available, return response from server,
        otherwise empty list
        """
        if not cdx_loader:
            return iter([])

        filters = []

        filters.append('!mime:warc/revisit')

        if digest and digest != '-':
            filters.append('digest:' + digest)

        params = dict(url=url,
                      closest=timestamp,
                      filter=filters)

        return cdx_loader(params)


# end  pywb.warc.resolvingloader


# begin pywb.warc.pathresolvers
# =================================================================
# PrefixResolver - convert cdx file entry to url with prefix
# if url contains specified string
# =================================================================
class PrefixResolver(object):
    def __init__(self, prefix, contains):
        self.prefix = prefix
        self.contains = contains if contains else ''

    def __call__(self, filename, cdx=None):
        # use os path seperator
        filename = filename.replace('/', os.path.sep)
        return [self.prefix + filename] if (self.contains in filename) else []

    def __repr__(self):
        if self.contains:
            return ("PrefixResolver('{0}', contains = '{1}')"
                    .format(self.prefix, self.contains))
        else:
            return "PrefixResolver('{0}')".format(self.prefix)


# =================================================================
class RedisResolver(object):
    def __init__(self, redis_url, key_prefix=None):
        self.redis_url = redis_url
        self.key_prefix = key_prefix if key_prefix else 'w:'
        self.redis = redis.StrictRedis.from_url(redis_url)

    def __call__(self, filename, cdx=None):
        redis_val = self.redis.hget(self.key_prefix + filename, 'path')
        return [to_native_str(redis_val, 'utf-8')] if redis_val else []

    def __repr__(self):
        return "RedisResolver('{0}')".format(self.redis_url)


# =================================================================
class PathIndexResolver(object):
    def __init__(self, pathindex_file):
        self.pathindex_file = pathindex_file

    def __call__(self, filename, cdx=None):
        with open(self.pathindex_file, 'rb') as reader:
            result = iter_exact(reader, filename.encode('utf-8'), b'\t')

            for pathline in result:
                paths = pathline.split(b'\t')[1:]
                for path in paths:
                    yield to_native_str(path, 'utf-8')

    def __repr__(self):  # pragma: no cover
        return "PathIndexResolver('{0}')".format(self.pathindex_file)


# =================================================================
class PathResolverMapper(object):
    def make_best_resolver(self, param):
        if isinstance(param, list):
            path = param[0]
            arg = param[1]
        else:
            path = param
            arg = None

        url_parts = urlsplit(path)

        if url_parts.scheme == 'redis':
            logging.debug('Adding Redis Index: ' + path)
            return RedisResolver(path, arg)

        if url_parts.scheme == 'file':
            path = url_parts.path
            path = url2pathname(path)

        if os.path.isfile(path):
            logging.debug('Adding Path Index: ' + path)
            return PathIndexResolver(path)

        # non-file paths always treated as prefix for now
        else:
            logging.debug('Adding Archive Path Source: ' + path)
            return PrefixResolver(path, arg)

    def __call__(self, paths):
        if isinstance(paths, list) or isinstance(paths, set):
            return list(map(self.make_best_resolver, paths))
        else:
            return [self.make_best_resolver(paths)]


# end pywb.warc.pathresolvers

# begin pywb.warc.archiveiterator
# =================================================================
class ArchiveIterator(object):
    """ Iterate over records in WARC and ARC files, both gzip chunk
    compressed and uncompressed

    The indexer will automatically detect format, and decompress
    if necessary.

    """

    GZIP_ERR_MSG = """
    ERROR: Non-chunked gzip file detected, gzip block continues
    beyond single record.

    This file is probably not a multi-chunk gzip but a single gzip file.

    To allow seek, a gzipped {1} must have each record compressed into
    a single gzip chunk and concatenated together.

    This file is likely still valid and you can use it by decompressing it:

    gunzip myfile.{0}.gz

    You can then also use the 'warc2warc' tool from the 'warc-tools'
    package which will create a properly chunked gzip file:

    warc2warc -Z myfile.{0} > myfile.{0}.gz
"""

    INC_RECORD = """\
    WARNING: Record not followed by newline, perhaps Content-Length is invalid
    Offset: {0}
    Remainder: {1}
"""

    def __init__(self, fileobj, no_record_parse=False,
                 verify_http=False):
        self.fh = fileobj

        self.loader = ArcWarcRecordLoader(verify_http=verify_http)
        self.reader = None

        self.offset = 0
        self.known_format = None

        self.member_info = None
        self.no_record_parse = no_record_parse

    def __call__(self, block_size=16384):
        """ iterate over each record
        """

        decomp_type = 'gzip'

        self.reader = DecompressingBufferedReader(self.fh,
                                                  block_size=block_size)
        self.offset = self.fh.tell()

        self.next_line = None

        raise_invalid_gzip = False
        empty_record = False
        record = None

        while True:
            try:
                curr_offset = self.fh.tell()
                record = self._next_record(self.next_line)
                if raise_invalid_gzip:
                    self._raise_invalid_gzip_err()

                yield record

            except EOFError:
                empty_record = True

            if record:
                self.read_to_end(record)

            if self.reader.decompressor:
                # if another gzip member, continue
                if self.reader.read_next_member():
                    continue

                # if empty record, then we're done
                elif empty_record:
                    break

                # otherwise, probably a gzip
                # containing multiple non-chunked records
                # raise this as an error
                else:
                    raise_invalid_gzip = True

            # non-gzip, so we're done
            elif empty_record:
                break

    def _raise_invalid_gzip_err(self):
        """ A gzip file with multiple ARC/WARC records, non-chunked
        has been detected. This is not valid for replay, so notify user
        """
        frmt = 'warc/arc'
        if self.known_format:
            frmt = self.known_format

        frmt_up = frmt.upper()

        msg = self.GZIP_ERR_MSG.format(frmt, frmt_up)
        raise Exception(msg)

    def _consume_blanklines(self):
        """ Consume blank lines that are between records
        - For warcs, there are usually 2
        - For arcs, may be 1 or 0
        - For block gzipped files, these are at end of each gzip envelope
          and are included in record length which is the full gzip envelope
        - For uncompressed, they are between records and so are NOT part of
          the record length

          count empty_size so that it can be substracted from
          the record length for uncompressed

          if first line read is not blank, likely error in WARC/ARC,
          display a warning
        """
        empty_size = 0
        first_line = True

        while True:
            line = self.reader.readline()
            if len(line) == 0:
                return None, empty_size

            stripped = line.rstrip()

            if len(stripped) == 0 or first_line:
                empty_size += len(line)

                if len(stripped) != 0:
                    # if first line is not blank,
                    # likely content-length was invalid, display warning
                    err_offset = self.fh.tell() - self.reader.rem_length() - empty_size
                    sys.stderr.write(self.INC_RECORD.format(err_offset, line))

                first_line = False
                continue

            return line, empty_size

    def read_to_end(self, record, payload_callback=None):
        """ Read remainder of the stream
        If a digester is included, update it
        with the data read
        """

        # already at end of this record, don't read until it is consumed
        if self.member_info:
            return None

        num = 0
        curr_offset = self.offset

        while True:
            b = record.stream.read(8192)
            if not b:
                break
            num += len(b)
            if payload_callback:
                payload_callback(b)

        """
        - For compressed files, blank lines are consumed
          since they are part of record length
        - For uncompressed files, blank lines are read later,
          and not included in the record length
        """
        # if self.reader.decompressor:
        self.next_line, empty_size = self._consume_blanklines()

        self.offset = self.fh.tell() - self.reader.rem_length()
        # if self.offset < 0:
        #    raise Exception('Not Gzipped Properly')

        if self.next_line:
            self.offset -= len(self.next_line)

        length = self.offset - curr_offset

        if not self.reader.decompressor:
            length -= empty_size

        self.member_info = (curr_offset, length)
        # return self.member_info
        # return next_line

    def _next_record(self, next_line):
        """ Use loader to parse the record from the reader stream
        Supporting warc and arc records
        """
        record = self.loader.parse_record_stream(self.reader,
                                                 next_line,
                                                 self.known_format,
                                                 self.no_record_parse)

        self.member_info = None

        # Track known format for faster parsing of other records
        self.known_format = record.format

        return record


# =================================================================
class ArchiveIndexEntryMixin(object):
    MIME_RE = re.compile('[; ]')

    def __init__(self):
        super(ArchiveIndexEntryMixin, self).__init__()
        self.reset_entry()

    def reset_entry(self):
        self['urlkey'] = ''
        self['metadata'] = ''
        self.buffer = None
        self.record = None

    def extract_mime(self, mime, def_mime='unk'):
        """ Utility function to extract mimetype only
        from a full content type, removing charset settings
        """
        self['mime'] = def_mime
        if mime:
            self['mime'] = self.MIME_RE.split(mime, 1)[0]
            self['_content_type'] = mime

    def extract_status(self, status_headers):
        """ Extract status code only from status line
        """
        self['status'] = status_headers.get_statuscode()
        if not self['status']:
            self['status'] = '-'
        elif self['status'] == '204' and 'Error' in status_headers.statusline:
            self['status'] = '-'

    def set_rec_info(self, offset, length):
        self['length'] = str(length)
        self['offset'] = str(offset)

    def merge_request_data(self, other, options):
        surt_ordered = options.get('surt_ordered', True)

        if other.record.rec_type != 'request':
            return False

        # two requests, not correct
        if self.record.rec_type == 'request':
            return False

        # merge POST/PUT body query
        post_query = other.get('_post_query')
        if post_query:
            url = append_post_query(self['url'], post_query)
            self['urlkey'] = canonicalize(url, surt_ordered)
            other['urlkey'] = self['urlkey']

        referer = other.record.status_headers.get_header('referer')
        if referer:
            self['_referer'] = referer

        return True


# =================================================================
class DefaultRecordParser(object):
    def __init__(self, **options):
        self.options = options
        self.entry_cache = {}
        self.digester = None
        self.buff = None

    def _create_index_entry(self, rec_type):
        try:
            entry = self.entry_cache[rec_type]
            entry.reset_entry()
        except:
            if self.options.get('cdxj'):
                entry = OrderedArchiveIndexEntry()
            else:
                entry = ArchiveIndexEntry()

            # don't reuse when using append post
            # entry may be cached
            if not self.options.get('append_post'):
                self.entry_cache[rec_type] = entry

        return entry

    def begin_payload(self, compute_digest, entry):
        if compute_digest:
            self.digester = hashlib.sha1()
        else:
            self.digester = None

        self.entry = entry
        entry.buffer = self.create_payload_buffer(entry)

    def handle_payload(self, buff):
        if self.digester:
            self.digester.update(buff)

        if self.entry and self.entry.buffer:
            self.entry.buffer.write(buff)

    def end_payload(self, entry):
        if self.digester:
            entry['digest'] = base64.b32encode(self.digester.digest()).decode('ascii')

        self.entry = None

    def create_payload_buffer(self, entry):
        return None

    def create_record_iter(self, raw_iter):
        append_post = self.options.get('append_post')
        include_all = self.options.get('include_all')
        block_size = self.options.get('block_size', 16384)
        surt_ordered = self.options.get('surt_ordered', True)
        minimal = self.options.get('minimal')

        if append_post and minimal:
            raise Exception('Sorry, minimal index option and ' +
                            'append POST options can not be used together')

        for record in raw_iter(block_size):
            entry = None

            if not include_all and not minimal and (record.status_headers.get_statuscode() == '-'):
                continue

            if record.format == 'warc':
                if (record.rec_type in ('request', 'warcinfo') and
                        not include_all and
                        not append_post):
                    continue

                elif (not include_all and
                              record.content_type == 'application/warc-fields'):
                    continue

                entry = self.parse_warc_record(record)
            elif record.format == 'arc':
                entry = self.parse_arc_record(record)

            if not entry:
                continue

            if entry.get('url') and not entry.get('urlkey'):
                entry['urlkey'] = canonicalize(entry['url'], surt_ordered)

            compute_digest = False

            if (entry.get('digest', '-') == '-' and
                        record.rec_type not in ('revisit', 'request', 'warcinfo')):

                compute_digest = True

            elif not minimal and record.rec_type == 'request' and append_post:
                method = record.status_headers.protocol
                len_ = record.status_headers.get_header('Content-Length')

                post_query = extract_post_query(method,
                                                entry.get('_content_type'),
                                                len_,
                                                record.stream)

                entry['_post_query'] = post_query

            entry.record = record

            self.begin_payload(compute_digest, entry)
            raw_iter.read_to_end(record, self.handle_payload)

            entry.set_rec_info(*raw_iter.member_info)
            self.end_payload(entry)

            yield entry

    def join_request_records(self, entry_iter):
        prev_entry = None

        for entry in entry_iter:
            if not prev_entry:
                prev_entry = entry
                continue

            # check for url match
            if (entry['url'] != prev_entry['url']):
                pass

            # check for concurrency also
            elif (entry.record.rec_headers.get_header('WARC-Concurrent-To') !=
                      prev_entry.record.rec_headers.get_header('WARC-Record-ID')):
                pass

            elif (entry.merge_request_data(prev_entry, self.options) or
                      prev_entry.merge_request_data(entry, self.options)):
                yield prev_entry
                yield entry
                prev_entry = None
                continue

            yield prev_entry
            prev_entry = entry

        if prev_entry:
            yield prev_entry

    # =================================================================
    def parse_warc_record(self, record):
        """ Parse warc record
        """

        entry = self._create_index_entry(record.rec_type)

        if record.rec_type == 'warcinfo':
            entry['url'] = record.rec_headers.get_header('WARC-Filename')
            entry['urlkey'] = entry['url']
            entry['_warcinfo'] = record.stream.read(record.length)
            return entry

        entry['url'] = record.rec_headers.get_header('WARC-Target-Uri')

        # timestamp
        entry['timestamp'] = iso_date_to_timestamp(record.rec_headers.
                                                   get_header('WARC-Date'))

        # mime
        if record.rec_type == 'revisit':
            entry['mime'] = 'warc/revisit'
        elif self.options.get('minimal'):
            entry['mime'] = '-'
        else:
            def_mime = '-' if record.rec_type == 'request' else 'unk'
            entry.extract_mime(record.status_headers.
                               get_header('Content-Type'),
                               def_mime)

        # status -- only for response records (by convention):
        if record.rec_type == 'response' and not self.options.get('minimal'):
            entry.extract_status(record.status_headers)
        else:
            entry['status'] = '-'

        # digest
        digest = record.rec_headers.get_header('WARC-Payload-Digest')
        entry['digest'] = digest
        if digest and digest.startswith('sha1:'):
            entry['digest'] = digest[len('sha1:'):]

        elif not entry.get('digest'):
            entry['digest'] = '-'

        # optional json metadata, if present
        metadata = record.rec_headers.get_header('WARC-Json-Metadata')
        if metadata:
            entry['metadata'] = metadata

        return entry

    # =================================================================
    def parse_arc_record(self, record):
        """ Parse arc record
        """
        if record.rec_type == 'arc_header':
            return None

        url = record.rec_headers.get_header('uri')
        url = url.replace('\r', '%0D')
        url = url.replace('\n', '%0A')
        # replace formfeed
        url = url.replace('\x0c', '%0C')
        # replace nulls
        url = url.replace('\x00', '%00')

        entry = self._create_index_entry(record.rec_type)
        entry['url'] = url

        # timestamp
        entry['timestamp'] = record.rec_headers.get_header('archive-date')
        if len(entry['timestamp']) > 14:
            entry['timestamp'] = entry['timestamp'][:14]

        if not self.options.get('minimal'):
            # mime
            entry.extract_mime(record.rec_headers.get_header('content-type'))

            # status
            entry.extract_status(record.status_headers)

        # digest
        entry['digest'] = '-'

        return entry

    def __call__(self, fh):
        aiter = ArchiveIterator(fh, self.options.get('minimal', False),
                                self.options.get('verify_http', False))

        entry_iter = self.create_record_iter(aiter)

        if self.options.get('append_post'):
            entry_iter = self.join_request_records(entry_iter)

        for entry in entry_iter:
            if (entry.record.rec_type in ('request', 'warcinfo') and
                    not self.options.get('include_all')):
                continue

            yield entry

    def open(self, filename):
        with open(filename, 'rb') as fh:
            for entry in self(fh):
                yield entry


class ArchiveIndexEntry(ArchiveIndexEntryMixin, dict):
    pass


class OrderedArchiveIndexEntry(ArchiveIndexEntryMixin, OrderedDict):
    pass


# end pywb.warc.archiveiterator

# begin pywb.warc.cdxIndexer
# =================================================================
class BaseCDXWriter(object):
    def __init__(self, out):
        self.out = codecs.getwriter('utf-8')(out)
        # self.out = out

    def __enter__(self):
        self._write_header()
        return self

    def write(self, entry, filename):
        if not entry.get('url') or not entry.get('urlkey'):
            return

        if entry.record.rec_type == 'warcinfo':
            return

        self.write_cdx_line(self.out, entry, filename)

    def __exit__(self, *args):
        return False


# =================================================================
class CDXJ(object):
    def _write_header(self):
        pass

    def write_cdx_line(self, out, entry, filename):
        out.write(entry['urlkey'])
        out.write(' ')
        out.write(entry['timestamp'])
        out.write(' ')

        outdict = OrderedDict()

        for n, v in six.iteritems(entry):
            if n in ('urlkey', 'timestamp'):
                continue

            if n.startswith('_'):
                continue

            if not v or v == '-':
                continue

            outdict[n] = v

        outdict['filename'] = filename
        out.write(json_encode(outdict))
        out.write('\n')


# =================================================================
class CDX09(object):
    def _write_header(self):
        self.out.write(' CDX N b a m s k r V g\n')

    def write_cdx_line(self, out, entry, filename):
        out.write(entry['urlkey'])
        out.write(' ')
        out.write(entry['timestamp'])
        out.write(' ')
        out.write(entry['url'])
        out.write(' ')
        out.write(entry['mime'])
        out.write(' ')
        out.write(entry['status'])
        out.write(' ')
        out.write(entry['digest'])
        out.write(' - ')
        out.write(entry['offset'])
        out.write(' ')
        out.write(filename)
        out.write('\n')


# =================================================================
class CDX11(object):
    def _write_header(self):
        self.out.write(' CDX N b a m s k r M S V g\n')

    def write_cdx_line(self, out, entry, filename):
        out.write(entry['urlkey'])
        out.write(' ')
        out.write(entry['timestamp'])
        out.write(' ')
        out.write(entry['url'])
        out.write(' ')
        out.write(entry['mime'])
        out.write(' ')
        out.write(entry['status'])
        out.write(' ')
        out.write(entry['digest'])
        out.write(' - - ')
        out.write(entry['length'])
        out.write(' ')
        out.write(entry['offset'])
        out.write(' ')
        out.write(filename)
        out.write('\n')


# =================================================================
class SortedCDXWriter(BaseCDXWriter):
    def __enter__(self):
        self.sortlist = []
        res = super(SortedCDXWriter, self).__enter__()
        self.actual_out = self.out
        return res

    def write(self, entry, filename):
        self.out = StringIO()
        super(SortedCDXWriter, self).write(entry, filename)
        line = self.out.getvalue()
        if line:
            insort(self.sortlist, line)

    def __exit__(self, *args):
        self.actual_out.write(''.join(self.sortlist))
        return False


# =================================================================
ALLOWED_EXT = ('.arc', '.arc.gz', '.warc', '.warc.gz')


# =================================================================
def _resolve_rel_path(path, rel_root):
    path = os.path.relpath(path, rel_root)
    if os.path.sep != '/':  # pragma: no cover
        path = path.replace(os.path.sep, '/')
    return path


# =================================================================
def iter_file_or_dir(inputs, recursive=True, rel_root=None):
    for input_ in inputs:
        if not os.path.isdir(input_):
            if not rel_root:
                filename = os.path.basename(input_)
            else:
                filename = _resolve_rel_path(input_, rel_root)

            yield input_, filename

        elif not recursive:
            for filename in os.listdir(input_):
                if filename.endswith(ALLOWED_EXT):
                    full_path = os.path.join(input_, filename)
                    if rel_root:
                        filename = _resolve_rel_path(full_path, rel_root)
                    yield full_path, filename

        else:
            for root, dirs, files in os.walk(input_):
                for filename in files:
                    if filename.endswith(ALLOWED_EXT):
                        full_path = os.path.join(root, filename)
                        if not rel_root:
                            rel_root = input_
                        rel_path = _resolve_rel_path(full_path, rel_root)
                        yield full_path, rel_path


# =================================================================
def remove_ext(filename):
    for ext in ALLOWED_EXT:
        if filename.endswith(ext):
            filename = filename[:-len(ext)]
            break

    return filename


# =================================================================
def cdx_filename(filename):
    return remove_ext(filename) + '.cdx'


# =================================================================
def get_cdx_writer_cls(options):
    if options.get('minimal'):
        options['cdxj'] = True

    writer_cls = options.get('writer_cls')
    if writer_cls:
        if not options.get('writer_add_mixin'):
            return writer_cls
    elif options.get('sort'):
        writer_cls = SortedCDXWriter
    else:
        writer_cls = BaseCDXWriter

    if options.get('cdxj'):
        format_mixin = CDXJ
    elif options.get('cdx09'):
        format_mixin = CDX09
    else:
        format_mixin = CDX11

    class CDXWriter(writer_cls, format_mixin):
        pass

    return CDXWriter


# =================================================================
def write_multi_cdx_index(output, inputs, **options):
    recurse = options.get('recurse', False)
    rel_root = options.get('rel_root')

    # write one cdx per dir
    if output != '-' and os.path.isdir(output):
        for fullpath, filename in iter_file_or_dir(inputs,
                                                   recurse,
                                                   rel_root):
            outpath = cdx_filename(filename)
            outpath = os.path.join(output, outpath)

            with open(outpath, 'wb') as outfile:
                with open(fullpath, 'rb') as infile:
                    writer = write_cdx_index(outfile, infile, filename,
                                             **options)

        return writer

    # write to one cdx file
    else:
        if output == '-':
            if hasattr(sys.stdout, 'buffer'):
                outfile = sys.stdout.buffer
            else:
                outfile = sys.stdout
        else:
            outfile = open(output, 'wb')

        writer_cls = get_cdx_writer_cls(options)
        record_iter = DefaultRecordParser(**options)

        with writer_cls(outfile) as writer:
            for fullpath, filename in iter_file_or_dir(inputs,
                                                       recurse,
                                                       rel_root):
                with open(fullpath, 'rb') as infile:
                    entry_iter = record_iter(infile)

                    for entry in entry_iter:
                        writer.write(entry, filename)

        return writer


# =================================================================
def write_cdx_index(outfile, infile, filename, **options):
    # filename = filename.encode(sys.getfilesystemencoding())

    writer_cls = get_cdx_writer_cls(options)

    with writer_cls(outfile) as writer:
        entry_iter = DefaultRecordParser(**options)(infile)

        for entry in entry_iter:
            writer.write(entry, filename)

    return writer


# end pywb.warc.cdxIndexer

# begin pywb.cdx.cdxobject
# =================================================================
class CDXObject(OrderedDict):
    """
    dictionary object representing parsed CDX line.
    """
    CDX_FORMATS = [
        # Public CDX Format
        [URLKEY, TIMESTAMP, ORIGINAL, MIMETYPE, STATUSCODE,
         DIGEST, LENGTH],

        # CDX 11 Format
        [URLKEY, TIMESTAMP, ORIGINAL, MIMETYPE, STATUSCODE,
         DIGEST, REDIRECT, ROBOTFLAGS, LENGTH, OFFSET, FILENAME],

        # CDX 10 Format
        [URLKEY, TIMESTAMP, ORIGINAL, MIMETYPE, STATUSCODE,
         DIGEST, REDIRECT, ROBOTFLAGS, OFFSET, FILENAME],

        # CDX 9 Format
        [URLKEY, TIMESTAMP, ORIGINAL, MIMETYPE, STATUSCODE,
         DIGEST, REDIRECT, OFFSET, FILENAME],

        # CDX 11 Format + 3 revisit resolve fields
        [URLKEY, TIMESTAMP, ORIGINAL, MIMETYPE, STATUSCODE,
         DIGEST, REDIRECT, ROBOTFLAGS, LENGTH, OFFSET, FILENAME,
         ORIG_LENGTH, ORIG_OFFSET, ORIG_FILENAME],

        # CDX 10 Format + 3 revisit resolve fields
        [URLKEY, TIMESTAMP, ORIGINAL, MIMETYPE, STATUSCODE,
         DIGEST, REDIRECT, ROBOTFLAGS, OFFSET, FILENAME,
         ORIG_LENGTH, ORIG_OFFSET, ORIG_FILENAME],

        # CDX 9 Format + 3 revisit resolve fields
        [URLKEY, TIMESTAMP, ORIGINAL, MIMETYPE, STATUSCODE,
         DIGEST, REDIRECT, OFFSET, FILENAME,
         ORIG_LENGTH, ORIG_OFFSET, ORIG_FILENAME],
    ]

    CDX_ALT_FIELDS = {
        'u': ORIGINAL,
        'original': ORIGINAL,

        'statuscode': STATUSCODE,
        's': STATUSCODE,

        'mimetype': MIMETYPE,
        'm': MIMETYPE,

        'l': LENGTH,
        's': LENGTH,

        'o': OFFSET,

        'd': DIGEST,

        't': TIMESTAMP,

        'k': URLKEY,

        'f': FILENAME
    }

    def __init__(self, cdxline=b''):
        OrderedDict.__init__(self)

        cdxline = cdxline.rstrip()
        self._from_json = False
        self._cached_json = None

        # Allows for filling the fields later or in a custom way
        if not cdxline:
            self.cdxline = cdxline
            return

        fields = cdxline.split(b' ', 2)
        # Check for CDX JSON
        if fields[-1].startswith(b'{'):
            self[URLKEY] = to_native_str(fields[0], 'utf-8')
            self[TIMESTAMP] = to_native_str(fields[1], 'utf-8')
            json_fields = json_decode(to_native_str(fields[-1], 'utf-8'))
            for n, v in six.iteritems(json_fields):
                n = to_native_str(n, 'utf-8')
                n = self.CDX_ALT_FIELDS.get(n, n)

                if n == 'url':
                    try:
                        v.encode('ascii')
                    except UnicodeEncodeError:
                        v = quote(v.encode('utf-8'), safe=':/')

                if n != 'filename':
                    v = to_native_str(v, 'utf-8')

                self[n] = v

            self.cdxline = cdxline
            self._from_json = True
            return

        more_fields = fields.pop().split(b' ')
        fields.extend(more_fields)

        cdxformat = None
        for i in self.CDX_FORMATS:
            if len(i) == len(fields):
                cdxformat = i

        if not cdxformat:
            msg = 'unknown {0}-field cdx format'.format(len(fields))
            raise CDXException(msg)

        for header, field in zip(cdxformat, fields):
            self[header] = to_native_str(field, 'utf-8')

        self.cdxline = cdxline

    def __setitem__(self, key, value):
        OrderedDict.__setitem__(self, key, value)

        # force regen on next __str__ call
        self.cdxline = None

        # force regen on next to_json() call
        self._cached_json = None

    def is_revisit(self):
        """return ``True`` if this record is a revisit record."""
        return (self.get(MIMETYPE) == 'warc/revisit' or
                self.get(FILENAME) == '-')

    def to_text(self, fields=None):
        """
        return plaintext CDX record (includes newline).
        if ``fields`` is ``None``, output will have all fields
        in the order they are stored.

        :param fields: list of field names to output.
        """
        if fields is None:
            return str(self) + '\n'

        try:
            result = ' '.join(str(self[x]) for x in fields) + '\n'
        except KeyError as ke:
            msg = 'Invalid field "{0}" found in fields= argument'
            msg = msg.format(str(ke))
            raise CDXException(msg)

        return result

    def to_json(self, fields=None):
        return self.conv_to_json(self, fields)

    @staticmethod
    def conv_to_json(obj, fields=None):
        """
        return cdx as json dictionary string
        if ``fields`` is ``None``, output will include all fields
        in order stored, otherwise only specified fields will be
        included

        :param fields: list of field names to output
        """
        if fields is None:
            return json_encode(OrderedDict(((x, obj[x]) for x in obj if not x.startswith('_')))) + '\n'

        result = json_encode(OrderedDict([(x, obj[x]) for x in fields if x in obj])) + '\n'

        return result

    def __str__(self):
        if self.cdxline:
            return to_native_str(self.cdxline, 'utf-8')

        if not self._from_json:
            return ' '.join(str(val) for val in six.itervalues(self))
        else:
            return json_encode(self)

    def to_cdxj(self, fields=None):
        prefix = self['urlkey'] + ' ' + self['timestamp'] + ' '
        dupe = OrderedDict(list(self.items())[2:])
        return prefix + self.conv_to_json(dupe, fields)

    def __lt__(self, other):
        if not self._cached_json:
            self._cached_json = self.to_json()

        if not other._cached_json:
            other._cached_json = other.to_json()

        res = self._cached_json < other._cached_json
        return res

    def __le__(self, other):
        if not self._cached_json:
            self._cached_json = self.to_json()

        if not other._cached_json:
            other._cached_json = other.to_json()

        res = (self._cached_json <= other._cached_json)
        return res


# =================================================================
class IDXObject(OrderedDict):
    FORMAT = ['urlkey', 'part', 'offset', 'length', 'lineno']
    NUM_REQ_FIELDS = len(FORMAT) - 1  # lineno is an optional field

    def __init__(self, idxline):
        OrderedDict.__init__(self)

        idxline = idxline.rstrip()
        fields = idxline.split(b'\t')

        if len(fields) < self.NUM_REQ_FIELDS:
            msg = 'invalid idx format: {0} fields found, {1} required'
            raise CDXException(msg.format(len(fields), self.NUM_REQ_FIELDS))

        for header, field in zip(self.FORMAT, fields):
            self[header] = to_native_str(field, 'utf-8')

        self['offset'] = int(self['offset'])
        self['length'] = int(self['length'])
        lineno = self.get('lineno')
        if lineno:
            self['lineno'] = int(lineno)

        self.idxline = idxline

    def to_text(self, fields=None):
        """
        return plaintext IDX record (including newline).

        :param fields: list of field names to output (currently ignored)
        """
        return str(self) + '\n'

    def to_json(self, fields=None):
        return json_encode(self) + '\n'

    def __str__(self):
        return to_native_str(self.idxline, 'utf-8')


# end pywb.cdx.cdxobject

# begin pywb.cdx.cdxops
# =================================================================
def cdx_load(sources, query, process=True):
    """
    merge text CDX lines from sources, return an iterator for
    filtered and access-checked sequence of CDX objects.

    :param sources: iterable for text CDX sources.
    :param process: bool, perform processing sorting/filtering/grouping ops
    """
    cdx_iter = create_merged_cdx_gen(sources, query)

    # page count is a special case, no further processing
    if query.page_count:
        return cdx_iter

    cdx_iter = make_obj_iter(cdx_iter, query)

    if process and not query.secondary_index_only:
        cdx_iter = process_cdx(cdx_iter, query)

    custom_ops = query.custom_ops
    for op in custom_ops:
        cdx_iter = op(cdx_iter, query)

    if query.output == 'text':
        cdx_iter = cdx_to_text(cdx_iter, query.fields)
    elif query.output == 'json':
        cdx_iter = cdx_to_json(cdx_iter, query.fields)

    return cdx_iter


# =================================================================
def cdx_to_text(cdx_iter, fields):
    for cdx in cdx_iter:
        yield cdx.to_text(fields)


# =================================================================
def cdx_to_json(cdx_iter, fields):
    for cdx in cdx_iter:
        yield cdx.to_json(fields)


# =================================================================
def process_cdx(cdx_iter, query):
    if query.resolve_revisits:
        cdx_iter = cdx_resolve_revisits(cdx_iter)

    filters = query.filters
    if filters:
        cdx_iter = cdx_filter(cdx_iter, filters)

    if query.from_ts or query.to_ts:
        cdx_iter = cdx_clamp(cdx_iter, query.from_ts, query.to_ts)

    collapse_time = query.collapse_time
    if collapse_time:
        cdx_iter = cdx_collapse_time_status(cdx_iter, collapse_time)

    closest = query.closest
    reverse = query.reverse
    limit = query.limit

    if closest:
        cdx_iter = cdx_sort_closest(closest, cdx_iter, limit)

    elif reverse:
        cdx_iter = cdx_reverse(cdx_iter, limit)

    elif limit:
        cdx_iter = cdx_limit(cdx_iter, limit)

    return cdx_iter


# =================================================================
def create_merged_cdx_gen(sources, query):
    """
    create a generator which loads and merges cdx streams
    ensures cdxs are lazy loaded
    """
    # Optimize: no need to merge if just one input
    if len(sources) == 1:
        cdx_iter = sources[0].load_cdx(query)
    else:
        source_iters = map(lambda src: src.load_cdx(query), sources)
        cdx_iter = merge(*(source_iters))

    for cdx in cdx_iter:
        yield cdx


# =================================================================
def make_obj_iter(text_iter, query):
    """
    convert text cdx stream to CDXObject/IDXObject.
    """
    if query.secondary_index_only:
        cls = IDXObject
    else:
        cls = CDXObject

    return (cls(line) for line in text_iter)


# =================================================================
def cdx_limit(cdx_iter, limit):
    """
    limit cdx to at most `limit`.
    """
    return (cdx for cdx, _ in zip(cdx_iter, range(limit)))


# =================================================================
def cdx_reverse(cdx_iter, limit):
    """
    return cdx records in reverse order.
    """
    # optimize for single last
    if limit == 1:
        last = None

        for cdx in cdx_iter:
            last = cdx

        if not last:
            return
        yield last

    reverse_cdxs = deque(maxlen=limit)

    for cdx in cdx_iter:
        reverse_cdxs.appendleft(cdx)

    for cdx in reverse_cdxs:
        yield cdx


# =================================================================
def cdx_filter(cdx_iter, filter_strings):
    """
    filter CDX by regex if each filter is :samp:`{field}:{regex}` form,
    apply filter to :samp:`cdx[{field}]`.
    """
    # Support single strings as well
    if isinstance(filter_strings, str):
        filter_strings = [filter_strings]

    filters = []

    class Filter:
        def __init__(self, string):
            # invert filter
            self.invert = string.startswith('!')
            if self.invert:
                string = string[1:]

            # exact match
            if string.startswith('='):
                string = string[1:]
                self.compare_func = self.exact
            # contains match
            elif string.startswith('~'):
                string = string[1:]
                self.compare_func = self.contains
            else:
                self.compare_func = self.regex

            parts = string.split(':', 1)
            # no field set, apply filter to entire cdx
            if len(parts) == 1:
                self.field = ''
            # apply filter to cdx[field]
            else:
                self.field = parts[0]
                self.field = CDXObject.CDX_ALT_FIELDS.get(self.field,
                                                          self.field)
                string = parts[1]

            # make regex if regex mode
            if self.compare_func == self.regex:
                self.regex = re.compile(string)
            else:
                self.filter_str = string

        def __call__(self, cdx):
            if not self.field:
                val = str(cdx)
            else:
                val = cdx.get(self.field, '')

            matched = self.compare_func(val)

            return matched ^ self.invert

        def exact(self, val):
            return (self.filter_str == val)

        def contains(self, val):
            return (self.filter_str in val)

        def regex(self, val):
            return self.regex.match(val) is not None

    filters = list(map(Filter, filter_strings))

    for cdx in cdx_iter:
        if all(x(cdx) for x in filters):
            yield cdx


# =================================================================
def cdx_clamp(cdx_iter, from_ts, to_ts):
    """
    Clamp by start and end ts
    """
    if from_ts and len(from_ts) < 14:
        from_ts = pad_timestamp(from_ts, PAD_14_DOWN)

    if to_ts and len(to_ts) < 14:
        to_ts = pad_timestamp(to_ts, PAD_14_UP)

    for cdx in cdx_iter:
        if from_ts and cdx[TIMESTAMP] < from_ts:
            continue

        if to_ts and cdx[TIMESTAMP] > to_ts:
            continue

        yield cdx


# =================================================================
def cdx_collapse_time_status(cdx_iter, timelen=10):
    """
    collapse by timestamp and status code.
    """
    timelen = int(timelen)

    last_token = None

    for cdx in cdx_iter:
        curr_token = (cdx[TIMESTAMP][:timelen], cdx.get(STATUSCODE, ''))

        # yield if last_dedup_time is diff, otherwise skip
        if curr_token != last_token:
            last_token = curr_token
            yield cdx


# =================================================================
def cdx_sort_closest(closest, cdx_iter, limit=10):
    """
    sort CDXCaptureResult by closest to timestamp.
    """
    closest_cdx = []
    closest_keys = []
    closest_sec = timestamp_to_sec(closest)

    for cdx in cdx_iter:
        sec = timestamp_to_sec(cdx[TIMESTAMP])
        key = abs(closest_sec - sec)

        # create tuple to sort by key
        # bisect.insort(closest_cdx, (key, cdx))

        i = bisect.bisect_right(closest_keys, key)
        closest_keys.insert(i, key)
        closest_cdx.insert(i, cdx)

        if len(closest_cdx) == limit:
            # assuming cdx in ascending order and keys have started increasing
            if key > closest_keys[-1]:
                break

        if len(closest_cdx) > limit:
            closest_cdx.pop()

    for cdx in closest_cdx:
        yield cdx

        # for cdx in map(lambda x: x[1], closest_cdx):
        #    yield cdx


# =================================================================
# resolve revisits

# Fields to append from cdx original to revisit
ORIG_TUPLE = [LENGTH, OFFSET, FILENAME]


def cdx_resolve_revisits(cdx_iter):
    """
    resolve revisits.

    this filter adds three fields to CDX: ``orig.length``, ``orig.offset``,
    and ``orig.filename``. for revisit records, these fields have corresponding
    field values in previous non-revisit (original) CDX record.
    They are all ``"-"`` for non-revisit records.
    """
    originals = {}

    for cdx in cdx_iter:
        is_revisit = cdx.is_revisit()

        digest = cdx.get(DIGEST)

        original_cdx = None

        # only set if digest is valid, otherwise no way to resolve
        if digest:
            original_cdx = originals.get(digest)

            if not original_cdx and not is_revisit:
                originals[digest] = cdx

        if original_cdx and is_revisit:
            fill_orig = lambda field: original_cdx.get(field, '-')
            # Transfer mimetype and statuscode
            if MIMETYPE in cdx:
                cdx[MIMETYPE] = original_cdx.get(MIMETYPE, '')
            if STATUSCODE in cdx:
                cdx[STATUSCODE] = original_cdx.get(STATUSCODE, '')
        else:
            fill_orig = lambda field: '-'

        # Always add either the original or empty '- - -'
        for field in ORIG_TUPLE:
            cdx['orig.' + field] = fill_orig(field)

        yield cdx


# end pywb.cdx.cdxops

# begin pywb.cdx.query
# =================================================================
class CDXQuery(object):
    def __init__(self, params):
        self.params = params
        url = self.url
        url = self.params.get('alt_url', url)
        if not self.params.get('matchType'):
            if url.startswith('*.'):
                url = self.params['url'] = url[2:]
                self.params['matchType'] = 'domain'
            elif url.endswith('*'):
                url = self.params['url'] = url[:-1]
                self.params['matchType'] = 'prefix'
            else:
                self.params['matchType'] = 'exact'

        start, end = calc_search_range(url=url,
                                       match_type=self.params['matchType'],
                                       url_canon=self.params.get('_url_canon'))

        self.params['key'] = start.encode('utf-8')
        self.params['end_key'] = end.encode('utf-8')

    @property
    def key(self):
        return self.params['key']

    @property
    def end_key(self):
        return self.params['end_key']

    def set_key(self, key, end_key):
        self.params['key'] = key
        self.params['end_key'] = end_key

    @property
    def url(self):
        try:
            return self.params['url']
        except KeyError:
            msg = 'A url= param must be specified to query the cdx server'
            raise CDXException(msg)

    @property
    def match_type(self):
        return self.params.get('matchType', 'exact')

    @property
    def is_exact(self):
        return self.match_type == 'exact'

    @property
    def allow_fuzzy(self):
        return self._get_bool('allowFuzzy')

    @property
    def output(self):
        return self.params.get('output', 'text')

    @property
    def limit(self):
        return int(self.params.get('limit', 100000))

    @property
    def collapse_time(self):
        return self.params.get('collapseTime')

    @property
    def resolve_revisits(self):
        return self._get_bool('resolveRevisits')

    @property
    def filters(self):
        return self.params.get('filter', [])

    @property
    def fields(self):
        v = self.params.get('fields')
        # check old param name
        if not v:
            v = self.params.get('fl')
        return v.split(',') if v else None

    @property
    def from_ts(self):
        return self.params.get('from') or self.params.get('from_ts')

    @property
    def to_ts(self):
        return self.params.get('to')

    @property
    def closest(self):
        # sort=closest is not required
        return self.params.get('closest')

    @property
    def reverse(self):
        # sort=reverse overrides reverse=0
        return (self._get_bool('reverse') or
                self.params.get('sort') == 'reverse')

    @property
    def custom_ops(self):
        return self.params.get('custom_ops', [])

    @property
    def secondary_index_only(self):
        return self._get_bool('showPagedIndex')

    @property
    def page(self):
        return int(self.params.get('page', 0))

    @property
    def page_size(self):
        return self.params.get('pageSize')

    @property
    def page_count(self):
        return self._get_bool('showNumPages')

    def _get_bool(self, name, def_val=False):
        v = self.params.get(name)
        if v:
            try:
                v = int(v)
            except ValueError as ex:
                v = (v.lower() == 'true')
        else:
            v = def_val

        return bool(v)

    def urlencode(self):
        return urlencode(self.params, True)


# end pywb.cdx.query

# begin pywb.cdx.cdxsource
# =================================================================
class CDXSource(object):
    """
    Represents any cdx index source
    """

    def load_cdx(self, query):  # pragma: no cover
        raise NotImplementedError('Implement in subclass')


# =================================================================
class CDXFile(CDXSource):
    """
    Represents a local plain-text .cdx file
    """

    def __init__(self, filename):
        self.filename = filename

    def load_cdx(self, query):
        return self._do_load_file(self.filename, query)

    @staticmethod
    def _do_load_file(filename, query):
        with open(filename, 'rb') as source:
            gen = iter_range(source, query.key,
                             query.end_key)
            for line in gen:
                yield line

    def __str__(self):
        return 'CDX File - ' + self.filename


# =================================================================
class RemoteCDXSource(CDXSource):
    """
    Represents a remote cdx server, to which requests will be proxied.

    Only ``url`` and ``match_type`` params are proxied at this time,
    the stream is passed through all other filters locally.
    """

    def __init__(self, filename, cookie=None, remote_processing=False):
        self.remote_url = filename
        self.cookie = cookie
        self.remote_processing = remote_processing

    def load_cdx(self, query):
        if self.remote_processing:
            remote_query = query
        else:
            # Only send url and matchType to remote
            remote_query = CDXQuery(dict(url=query.url,
                                         matchType=query.match_type))

        urlparams = remote_query.urlencode()

        try:
            request = Request(self.remote_url + '?' + urlparams)

            if self.cookie:
                request.add_header('Cookie', self.cookie)

            response = urlopen(request)

        except HTTPError as e:
            if e.code == 403:
                raise AccessException('Access Denied')
            elif e.code == 404:
                # return empty list for consistency with other cdx sources
                # will be converted to 404 if no other retry
                return []
            elif e.code == 400:
                raise BadRequestException()
            else:
                raise WbException('Invalid response from remote cdx server')

        return iter(response)

    def __str__(self):
        if self.remote_processing:
            return 'Remote CDX Server: ' + self.remote_url
        else:
            return 'Remote CDX Source: ' + self.remote_url


# =================================================================
class RedisCDXSource(CDXSource):
    DEFAULT_KEY_PREFIX = b'c:'

    def __init__(self, redis_url, config=None):
        import redis

        parts = redis_url.split('/')
        if len(parts) > 4:
            self.cdx_key = parts[4].encode('utf-8')
            redis_url = 'redis://' + parts[2] + '/' + parts[3]
        else:
            self.cdx_key = None

        self.redis_url = redis_url
        self.redis = redis.StrictRedis.from_url(redis_url)

        self.key_prefix = self.DEFAULT_KEY_PREFIX

    def load_cdx(self, query):
        """
        Load cdx from redis cache, from an ordered list

        If cdx_key is set, treat it as cdx file and load use
        zrangebylex! (Supports all match types!)

        Otherwise, assume a key per-url and load all entries for that key.
        (Only exact match supported)
        """

        if self.cdx_key:
            return self.load_sorted_range(query, self.cdx_key)
        else:
            return self.load_single_key(query.key)

    def load_sorted_range(self, query, cdx_key):
        cdx_list = self.redis.zrangebylex(cdx_key,
                                          b'[' + query.key,
                                          b'(' + query.end_key)

        return iter(cdx_list)

    def load_single_key(self, key):
        # ensure only url/surt is part of key
        key = key.split(b' ')[0]
        cdx_list = self.redis.zrange(self.key_prefix + key, 0, -1)

        # key is not part of list, so prepend to each line
        key += b' '
        cdx_list = list(map(lambda x: key + x, cdx_list))
        return cdx_list

    def __str__(self):
        return 'Redis - ' + self.redis_url


# end pywb.cdx.cdxsource


# begin pywb.cdx.cdxdomainspecific
# =================================================================
def load_domain_specific_cdx_rules(ds_rules_file, surt_ordered):
    canon = None
    fuzzy = None

    # Load Canonicalizer Rules
    rules = RuleSet(CDXDomainSpecificRule, 'canonicalize',
                    ds_rules_file=ds_rules_file)

    if not surt_ordered:
        for rule in rules.rules:
            rule.unsurt()

    if rules:
        canon = CustomUrlCanonicalizer(rules, surt_ordered)

    # Load Fuzzy Lookup Rules
    rules = RuleSet(CDXDomainSpecificRule, 'fuzzy_lookup',
                    ds_rules_file=ds_rules_file)

    if not surt_ordered:
        for rule in rules.rules:
            rule.unsurt()

    if rules:
        fuzzy = FuzzyQuery(rules)

    logging.debug('CustomCanonilizer? ' + str(bool(canon)))
    logging.debug('FuzzyMatcher? ' + str(bool(canon)))
    return (canon, fuzzy)


# =================================================================
class CustomUrlCanonicalizer(UrlCanonicalizer):
    def __init__(self, rules, surt_ordered=True):
        super(CustomUrlCanonicalizer, self).__init__(surt_ordered)
        self.rules = rules

    def __call__(self, url):
        urlkey = super(CustomUrlCanonicalizer, self).__call__(url)

        for rule in self.rules.iter_matching(urlkey):
            m = rule.regex.match(urlkey)
            if not m:
                continue

            if rule.replace:
                return m.expand(rule.replace)

        return urlkey


# =================================================================
class FuzzyQuery(object):
    def __init__(self, rules):
        self.rules = rules

    def __call__(self, query):
        matched_rule = None

        urlkey = to_native_str(query.key, 'utf-8')
        url = query.url
        filter_ = query.filters
        output = query.output

        for rule in self.rules.iter_matching(urlkey):
            m = rule.regex.search(urlkey)
            if not m:
                continue

            matched_rule = rule

            groups = m.groups()
            for g in groups:
                for f in matched_rule.filter:
                    filter_.append(f.format(g))

            break

        if not matched_rule:
            return None

        repl = '?'
        if matched_rule.replace:
            repl = matched_rule.replace

        inx = url.find(repl)
        if inx > 0:
            url = url[:inx + len(repl)]

        if matched_rule.match_type == 'domain':
            host = urlsplit(url).netloc
            # remove the subdomain
            url = host.split('.', 1)[1]

        params = query.params
        params.update({'url': url,
                       'matchType': matched_rule.match_type,
                       'filter': filter_})

        if 'reverse' in params:
            del params['reverse']

        if 'closest' in params:
            del params['closest']

        if 'end_key' in params:
            del params['end_key']

        return params


# =================================================================
class CDXDomainSpecificRule(BaseRule):
    DEFAULT_FILTER = ['~urlkey:{0}']
    DEFAULT_MATCH_TYPE = 'prefix'

    def __init__(self, name, config):
        super(CDXDomainSpecificRule, self).__init__(name, config)

        if not isinstance(config, dict):
            self.regex = self.make_regex(config)
            self.replace = None
            self.filter = self.DEFAULT_FILTER
            self.match_type = self.DEFAULT_MATCH_TYPE
        else:
            self.regex = self.make_regex(config.get('match'))
            self.replace = config.get('replace')
            self.filter = config.get('filter', self.DEFAULT_FILTER)
            self.match_type = config.get('type', self.DEFAULT_MATCH_TYPE)

    def unsurt(self):
        """
        urlkey is assumed to be in surt format by default
        In the case of non-surt format, this method is called
        to desurt any urls
        """
        self.url_prefix = list(map(unsurt, self.url_prefix))
        if self.regex:
            self.regex = re.compile(unsurt(self.regex.pattern))

        if self.replace:
            self.replace = unsurt(self.replace)

    @staticmethod
    def make_regex(config):
        # just query args
        if isinstance(config, list):
            string = CDXDomainSpecificRule.make_query_match_regex(config)

        # split out base and args
        elif isinstance(config, dict):
            string = config.get('regex', '')
            string += CDXDomainSpecificRule.make_query_match_regex(
                config.get('args', []))

        # else assume string
        else:
            string = str(config)

        return re.compile(string)

    @staticmethod
    def make_query_match_regex(params_list):
        params_list.sort()

        def conv(value):
            return '[?&]({0}=[^&]+)'.format(re.escape(value))

        params_list = list(map(conv, params_list))
        final_str = '.*'.join(params_list)
        return final_str


# end pywb.cdx.cdxdomainspecific


# begin pywb.cdx.zipnum
# =================================================================
class ZipBlocks:
    def __init__(self, part, offset, length, count):
        self.part = part
        self.offset = offset
        self.length = length
        self.count = count


# =================================================================
# TODO: see if these could be combined with warc path resolvers

class LocMapResolver(object):
    """ Lookup shards based on a file mapping
    shard name to one or more paths. The entries are
    tab delimited.
    """

    def __init__(self, loc_summary, loc_filename):
        # initial loc map
        self.loc_map = {}
        self.loc_mtime = 0
        if not loc_filename:
            splits = os.path.splitext(loc_summary)
            loc_filename = splits[0] + '.loc'
        self.loc_filename = loc_filename

        self.load_loc()

    def load_loc(self):
        # check modified time of current file before loading
        new_mtime = os.path.getmtime(self.loc_filename)
        if (new_mtime == self.loc_mtime):
            return

        # update loc file mtime
        self.loc_mtime = new_mtime

        local_dir = os.path.dirname(self.loc_filename)

        def res_path(pathname):
            if '://' not in pathname:
                pathname = os.path.join(local_dir, pathname)
            return pathname

        logging.debug('Loading loc from: ' + self.loc_filename)
        with open(self.loc_filename, 'r') as fh:
            for line in fh:
                parts = line.rstrip().split('\t')

                paths = [res_path(pathname) for pathname in parts[1:]]
                self.loc_map[parts[0]] = paths

    def __call__(self, part, query):
        return self.loc_map[part]


# =================================================================
class LocPrefixResolver(object):
    """ Use a prefix lookup, where the prefix can either be a fixed
    string or can be a regex replacement of the index summary path
    """

    def __init__(self, loc_summary, loc_config):
        import re
        loc_match = loc_config.get('match', '().*')
        loc_replace = loc_config['replace']
        loc_summary = os.path.dirname(loc_summary) + '/'
        self.prefix = re.sub(loc_match, loc_replace, loc_summary)

    def load_loc(self):
        pass

    def __call__(self, part, query):
        return [self.prefix + part]


# =================================================================
class ZipNumCluster(CDXSource):
    DEFAULT_RELOAD_INTERVAL = 10  # in minutes
    DEFAULT_MAX_BLOCKS = 10

    def __init__(self, summary, config=None):
        self.max_blocks = self.DEFAULT_MAX_BLOCKS

        self.loc_resolver = None

        loc = None
        cookie_maker = None
        reload_ival = self.DEFAULT_RELOAD_INTERVAL

        if config:
            loc = config.get('shard_index_loc')
            cookie_maker = config.get('cookie_maker')

            self.max_blocks = config.get('max_blocks', self.max_blocks)

            reload_ival = config.get('reload_interval', reload_ival)

        if isinstance(loc, dict):
            self.loc_resolver = LocPrefixResolver(summary, loc)
        else:
            self.loc_resolver = LocMapResolver(summary, loc)

        self.summary = summary

        # reload interval
        self.loc_update_time = datetime.datetime.now()
        self.reload_interval = datetime.timedelta(minutes=reload_ival)

        self.blk_loader = BlockLoader(cookie_maker=cookie_maker)

    #    @staticmethod
    #    def reload_timed(timestamp, val, delta, func):
    #        now = datetime.datetime.now()
    #        if now - timestamp >= delta:
    #            func()
    #            return now
    #        return None
    #
    #    def reload_loc(self):
    #        reload_time = self.reload_timed(self.loc_update_time,
    #                                        self.loc_map,
    #                                        self.reload_interval,
    #                                        self.load_loc)
    #
    #        if reload_time:
    #            self.loc_update_time = reload_time

    def load_cdx(self, query):
        self.loc_resolver.load_loc()
        return self._do_load_cdx(self.summary, query)

    def _do_load_cdx(self, filename, query):
        reader = open(filename, 'rb')

        idx_iter = self.compute_page_range(reader, query)

        if query.secondary_index_only or query.page_count:
            return idx_iter

        blocks = self.idx_to_cdx(idx_iter, query)

        def gen_cdx():
            for blk in blocks:
                for cdx in blk:
                    yield cdx

        return gen_cdx()

    def _page_info(self, pages, pagesize, blocks):
        info = dict(pages=pages,
                    pageSize=pagesize,
                    blocks=blocks)
        return json.dumps(info) + '\n'

    def compute_page_range(self, reader, query):
        pagesize = query.page_size
        if not pagesize:
            pagesize = self.max_blocks
        else:
            pagesize = int(pagesize)

        last_line = None

        # Get End
        end_iter = search(reader, query.end_key, prev_size=1)

        try:
            end_line = six.next(end_iter)
        except StopIteration:
            last_line = read_last_line(reader)
            end_line = last_line

        # Get Start
        first_iter = iter_range(reader,
                                query.key,
                                query.end_key,
                                prev_size=1)

        try:
            first_line = six.next(first_iter)
        except StopIteration:
            if end_line == last_line and query.key >= last_line:
                first_line = last_line
            else:
                reader.close()
                if query.page_count:
                    yield self._page_info(0, pagesize, 0)
                    return
                else:
                    raise

        first = IDXObject(first_line)

        end = IDXObject(end_line)

        try:
            blocks = end['lineno'] - first['lineno']
            total_pages = int(blocks / pagesize) + 1
        except:
            blocks = -1
            total_pages = 1

        if query.page_count:
            # same line, so actually need to look at cdx
            # to determine if it exists
            if blocks == 0:
                try:
                    block_cdx_iter = self.idx_to_cdx([first_line], query)
                    block = six.next(block_cdx_iter)
                    cdx = six.next(block)
                except StopIteration:
                    total_pages = 0
                    blocks = -1

            yield self._page_info(total_pages, pagesize, blocks + 1)
            reader.close()
            return

        curr_page = query.page
        if curr_page >= total_pages or curr_page < 0:
            msg = 'Page {0} invalid: First Page is 0, Last Page is {1}'
            reader.close()
            raise CDXException(msg.format(curr_page, total_pages - 1))

        startline = curr_page * pagesize
        endline = startline + pagesize - 1
        if blocks >= 0:
            endline = min(endline, blocks)

        if curr_page == 0:
            yield first_line
        else:
            startline -= 1

        idxiter = itertools.islice(first_iter, startline, endline)
        for idx in idxiter:
            yield idx

        reader.close()

    def search_by_line_num(self, reader, line):  # pragma: no cover
        def line_cmp(line1, line2):
            line1_no = int(line1.rsplit(b'\t', 1)[-1])
            line2_no = int(line2.rsplit(b'\t', 1)[-1])
            return cmp(line1_no, line2_no)

        line_iter = search(reader, line, compare_func=line_cmp)
        yield six.next(line_iter)

    def idx_to_cdx(self, idx_iter, query):
        blocks = None
        ranges = []

        for idx in idx_iter:
            idx = IDXObject(idx)

            if (blocks and blocks.part == idx['part'] and
                            blocks.offset + blocks.length == idx['offset'] and
                        blocks.count < self.max_blocks):

                blocks.length += idx['length']
                blocks.count += 1
                ranges.append(idx['length'])

            else:
                if blocks:
                    yield self.block_to_cdx_iter(blocks, ranges, query)

                blocks = ZipBlocks(idx['part'],
                                   idx['offset'],
                                   idx['length'],
                                   1)

                ranges = [blocks.length]

        if blocks:
            yield self.block_to_cdx_iter(blocks, ranges, query)

    def block_to_cdx_iter(self, blocks, ranges, query):
        last_exc = None
        last_traceback = None

        try:
            locations = self.loc_resolver(blocks.part, query)
        except:
            raise Exception('No Locations Found for: ' + blocks.part)

        for location in self.loc_resolver(blocks.part, query):
            try:
                return self.load_blocks(location, blocks, ranges, query)
            except Exception as exc:
                last_exc = exc
                import sys
                last_traceback = sys.exc_info()[2]

        if last_exc:
            six.reraise(Exception, last_exc, last_traceback)
            # raise last_exc
        else:
            raise Exception('No Locations Found for: ' + blocks.part)

    def load_blocks(self, location, blocks, ranges, query):
        """ Load one or more blocks of compressed cdx lines, return
        a line iterator which decompresses and returns one line at a time,
        bounded by query.key and query.end_key
        """

        if (logging.getLogger().getEffectiveLevel() <= logging.DEBUG):
            msg = 'Loading {b.count} blocks from {loc}:{b.offset}+{b.length}'
            logging.debug(msg.format(b=blocks, loc=location))

        reader = self.blk_loader.load(location, blocks.offset, blocks.length)

        def decompress_block(range_):
            decomp = gzip_decompressor()
            buff = decomp.decompress(reader.read(range_))
            for line in BytesIO(buff):
                yield line

        iter_ = itertools.chain(*map(decompress_block, ranges))

        # start bound
        iter_ = linearsearch(iter_, query.key)

        # end bound
        iter_ = itertools.takewhile(lambda line: line < query.end_key, iter_)
        return iter_

    def __str__(self):
        return 'ZipNum Cluster: {0}, {1}'.format(self.summary,
                                                 self.loc_resolver)


# end pywb.cdx.zipnum




# =================================================================
def main(args=None):
    description = """
Generate .cdx index files for WARCs and ARCs
Compressed (.warc.gz / .arc.gz) or uncompressed (.warc / .arc) formats
are supported.
"""

    epilog = """
Some examples:

* Create "example.cdx" index from example.warc.gz
{0} ./cdx/example.cdx ./warcs/example.warc.gz

* Create "combined.cdx", a combined, sorted index of all warcs in ./warcs/
{0} --sort combined.cdx ./warcs/

* Create a sorted cdx per file in ./cdx/ for each archive file in ./warcs/
{0} --sort ./cdx/ ./warcs/
""".format(os.path.basename(sys.argv[0]))

    sort_help = """
Sort the output to each file before writing to create a total ordering
"""

    unsurt_help = """
Convert SURT (Sort-friendly URI Reordering Transform) back to regular
urls for the cdx key. Default is to use SURT keys.
Not-recommended for new cdx, use only for backwards-compatibility.
"""

    verify_help = """
Verify HTTP protocol (1.0/1.1) status in response records and http verb
on request records, ensuring the protocol or verb matches the expected list.
Raise an exception on failure. (This was previously the default behavior).
"""

    cdx09_help = """
Use older 9-field cdx format, default is 11-cdx field
"""
    minimal_json_help = """
CDX JSON output, but with minimal fields only, available  w/o parsing
http record. The fields are: canonicalized url, timestamp,
original url, digest, archive offset, archive length
and archive filename. mimetype is included to indicate warc/revisit only.

This option skips record parsing and will not work with
POST append (-p) option
"""

    json_help = """
Output CDX JSON format per line, with url timestamp first,
followed by a json dict for all other fields:
url timestamp { ... }
"""

    output_help = """
Output file or directory.
- If directory, each input file is written to a seperate output file
  with a .cdx extension
- If output is '-', output is written to stdout
"""

    input_help = """
Input file or directory.
- If directory, all archive files from that directory are read
"""

    allrecords_help = """
Include All records.
currently includes the 'request' records in addition to all
response records
"""

    post_append_help = """
For POST requests, append form query to url key.
(Only applies to form url encoded posts)
"""

    recurse_dirs_help = """
Recurse through all subdirectories if the input is a directory
"""

    dir_root_help = """
Make CDX filenames relative to specified root directory,
instead of current working directory
"""

    parser = ArgumentParser(description=description,
                            epilog=epilog,
                            formatter_class=RawTextHelpFormatter)

    parser.add_argument('-s', '--sort',
                        action='store_true',
                        help=sort_help)

    parser.add_argument('-a', '--allrecords',
                        action='store_true',
                        help=allrecords_help)

    parser.add_argument('-p', '--postappend',
                        action='store_true',
                        help=post_append_help)

    parser.add_argument('-r', '--recurse',
                        action='store_true',
                        help=recurse_dirs_help)

    parser.add_argument('-d', '--dir-root',
                        help=dir_root_help)

    parser.add_argument('-u', '--unsurt',
                        action='store_true',
                        help=unsurt_help)

    parser.add_argument('-v', '--verify',
                        action='store_true',
                        help=verify_help)

    group = parser.add_mutually_exclusive_group()
    group.add_argument('-9', '--cdx09',
                       action='store_true',
                       help=cdx09_help)

    group.add_argument('-j', '--cdxj',
                       action='store_true',
                       help=json_help)

    parser.add_argument('-mj', '--minimal-cdxj',
                        action='store_true',
                        help=minimal_json_help)

    parser.add_argument('output', nargs='?', default='-', help=output_help)
    parser.add_argument('inputs', nargs='+', help=input_help)

    cmd = parser.parse_args(args=args)

    write_multi_cdx_index(cmd.output, cmd.inputs,
                          sort=cmd.sort,
                          surt_ordered=not cmd.unsurt,
                          include_all=cmd.allrecords,
                          append_post=cmd.postappend,
                          recurse=cmd.recurse,
                          rel_root=cmd.dir_root,
                          verify_http=cmd.verify,
                          cdx09=cmd.cdx09,
                          cdxj=cmd.cdxj,
                          minimal=cmd.minimal_cdxj)


if __name__ == '__main__':
    multiprocessing.freeze_support()
    main()
