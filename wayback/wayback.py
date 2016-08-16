import base64
import brotli
import calendar
import cgi
import codecs
import collections
import datetime
import hashlib
import heapq
import hmac
import json
import logging
import os
import pkg_resources
import re
import requests
import shutil
import six
import surt
import sys
import time
import yaml
import socket
import ssl
import zlib
import pprint
import pkgutil
import webencodings
import yaml
import re

try:  # pragma: no cover
    import uwsgi
    uwsgi_cache = True
except ImportError:
    uwsgi_cache = False


from redis import StrictRedis

from __future__ import absolute_import

from distutils.util import strtobool
from pkg_resources import resource_string

from argparse import ArgumentParser, RawTextHelpFormatter

from six.moves.urllib.parse import urlencode, quote
from six.moves.urllib.parse import parse_qs
from six.moves.urllib.request import pathname2url, url2pathname
from six.moves.urllib.parse import urljoin, unquote_plus, urlsplit
from six.moves.urllib.parse import urlsplit, urlunsplit
from six.moves.urllib.parse import quote_plus, unquote_plus
import six.moves.urllib.parse as urlparse
from six.moves.http_cookies import SimpleCookie, CookieError
from six.moves import map
from six.moves import zip
from six.moves import range
from six import iteritems
from six import StringIO

from pprint import pformat
from copy import copy

from bisect import insort

from email.utils import parsedate, formatdate

from watchdog.observers import Observer
from watchdog.events import RegexMatchingEventHandler

from io import open, BytesIO

from json import loads as json_decode

from jinja2 import Environment
from jinja2 import FileSystemLoader, PackageLoader, ChoiceLoader

from tempfile import SpooledTemporaryFile

from datetime import datetime, timedelta

if os.environ.get('GEVENT_MONKEY_PATCH') == '1':  #pragma: no cover
    # Use gevent if available
    try:
        from gevent.monkey import patch_all; patch_all()
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

# TODO(FIX THIS!!!)
from pywb import DEFAULT_CONFIG
#=================================================================
DEFAULT_RULES_FILE = 'pywb/rules.yaml'

DEFAULT_PORT = 8080

WRAP_WIDTH = 80

FILTERS = {}

#=================================================================
DEFAULT_CONFIG_FILE = 'config.yaml'

DATE_TIMESPLIT = re.compile(r'[^\d]')

TIMESTAMP_14 = '%Y%m%d%H%M%S'
ISO_DT = '%Y-%m-%dT%H:%M:%SZ'

PAD_14_DOWN = '10000101000000'
PAD_14_UP =   '29991231235959'
PAD_6_UP =    '299912'


LINK_FORMAT = 'application/link-format'

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

#=================================================================
# begin pywb.utils.loaders

#=================================================================
def is_http(filename):
    return filename.startswith(('http://', 'https://'))


#=================================================================
def to_file_url(filename):
    """ Convert a filename to a file:// url
    """
    url = os.path.abspath(filename)
    url = urljoin('file:', pathname2url(url))
    return url


#=================================================================
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


#=================================================================
def to_native_str(value, encoding='iso-8859-1', func=lambda x: x):
    if isinstance(value, str):
        return value

    if six.PY3 and isinstance(value, six.binary_type):  #pragma: no cover
        return func(value.decode(encoding))
    elif six.PY2 and isinstance(value, six.text_type):  #pragma: no cover
        return func(value.encode(encoding))


#=================================================================
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


#=================================================================
def amf_parse(string, environ):
    try:
        from pyamf import remoting

        res = remoting.decode(BytesIO(string))

        #print(res)
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
        #print(query)
        return query

    except Exception as e:
        import traceback
        traceback.print_exc()
        print(e)
        return None


#=================================================================
def append_post_query(url, post_query):
    if not post_query:
        return url

    if '?' not in url:
        url += '?'
    else:
        url += '&'

    url += post_query
    return url


#=================================================================
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


#=================================================================
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


#=================================================================
class BaseLoader(object):
    def __init__(self, **kwargs):
        pass

    def load(self, url, offset=0, length=-1):
        raise NotImplemented()


#=================================================================
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


#=================================================================
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


#=================================================================
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


#=================================================================
class S3Loader(BaseLoader):
    def __init__(self, **kwargs):
        self.s3conn = None
        self.aws_access_key_id = kwargs.get('aws_access_key_id')
        self.aws_secret_access_key = kwargs.get('aws_secret_access_key')

    def load(self, url, offset, length):
        if not s3_avail:  #pragma: no cover
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
            except Exception:  #pragma: no cover
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


#=================================================================
# Signed Cookie-Maker
#=================================================================

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


#=================================================================
# Limit Reader
#=================================================================
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

    #return time.strptime(pad_timestamp(string), TIMESTAMP_14)


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


#end pywb.utils.timeutils

# begin pywb.utils.statusandheaders
#=================================================================
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
            assert(code > 0)
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


#=================================================================
def _strip_count(string, total_read):
    length = len(string)
    return string.rstrip(), total_read + length


#=================================================================
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


#=================================================================
class StatusAndHeadersParserException(Exception):
    """
    status + headers parsing exception
    """
    def __init__(self, msg, statusline):
        super(StatusAndHeadersParserException, self).__init__(msg)
        self.statusline = statusline
# end pywb.utils.statusandheaders


# begin pywb.utils.bufferedreader

#=================================================================
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


#=================================================================
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


#=================================================================
class DecompressingBufferedReader(BufferedReader):
    """
    A BufferedReader which defaults to gzip decompression,
    (unless different type specified)
    """
    def __init__(self, *args, **kwargs):
        if 'decomp_type' not in kwargs:
            kwargs['decomp_type'] = 'gzip'
        super(DecompressingBufferedReader, self).__init__(*args, **kwargs)


#=================================================================
class ChunkedDataException(Exception):
    def __init__(self, msg, data=b''):
        Exception.__init__(self, msg)
        self.data = data


#=================================================================
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

#=================================================================
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


#=================================================================
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

# begin pywb.framework.wbrequestresponse
#=================================================================
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


#=================================================================
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
#=================================================================
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


#=================================================================
class WbUrl(BaseWbUrl):
    # Regexs
    # ======================
    QUERY_REGEX = re.compile('^(?:([\w\-:]+)/)?(\d*)[*-](\d*)/?(.+)$')
    REPLAY_REGEX = re.compile('^(\d*)([a-z]+_)?/{1,3}(.+)$')
    #LATEST_REPLAY_REGEX = re.compile('^\w_)')

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

        domain = quote(domain)#, safe=r':\/')

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
        #if inx < 0:
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


# begin pywb.rewrite.cookie_rewriter

#================================================================
class WbUrlBaseCookieRewriter(object):
    """ Base Cookie rewriter for wburl-based requests.
    """
    UTC_RX = re.compile('((?:.*)Expires=(?:.*))UTC', re.I)

    def __init__(self, url_rewriter):
        self.url_rewriter = url_rewriter

    def rewrite(self, cookie_str, header='Set-Cookie'):
        results = []
        cookie_str = self.UTC_RX.sub('\\1GMT', cookie_str)
        try:
            cookie = SimpleCookie(cookie_str)
        except CookieError:
            import traceback
            traceback.print_exc()
            return results

        for name, morsel in six.iteritems(cookie):
            morsel = self.rewrite_cookie(name, morsel)

            self._filter_morsel(morsel)
            results.append((header, morsel.OutputString()))

        return results

    def _filter_morsel(self, morsel):
        path = morsel.get('path')
        if path:
            inx = path.find(self.url_rewriter.rel_prefix)
            if inx > 0:
                morsel['path'] = path[inx:]

        if not self.url_rewriter.full_prefix.startswith('https://'):
            # also remove secure to avoid issues when
            # proxying over plain http
            if morsel.get('secure'):
                del morsel['secure']

        if not self.url_rewriter.rewrite_opts.get('is_live'):
            self._remove_age_opts(morsel)

    def _remove_age_opts(self, morsel):
        # remove expires as it refers to archived time
        if morsel.get('expires'):
            del morsel['expires']

        # don't use max-age, just expire at end of session
        if morsel.get('max-age'):
            del morsel['max-age']


#=================================================================
class RemoveAllCookiesRewriter(WbUrlBaseCookieRewriter):
    def rewrite(self, cookie_str, header='Set-Cookie'):
        return []


#=================================================================
class MinimalScopeCookieRewriter(WbUrlBaseCookieRewriter):
    """
    Attempt to rewrite cookies to minimal scope possible

    If path present, rewrite path to current rewritten url only
    If domain present, remove domain and set to path prefix
    """

    def rewrite_cookie(self, name, morsel):
        # if domain set, no choice but to expand cookie path to root
        if morsel.get('domain'):
            del morsel['domain']
            morsel['path'] = self.url_rewriter.rel_prefix
        # else set cookie to rewritten path
        elif morsel.get('path'):
            morsel['path'] = self.url_rewriter.rewrite(morsel['path'])

        return morsel


#=================================================================
class HostScopeCookieRewriter(WbUrlBaseCookieRewriter):
    """
    Attempt to rewrite cookies to current host url..

    If path present, rewrite path to current host. Only makes sense in live
    proxy or no redirect mode, as otherwise timestamp may change.

    If domain present, remove domain and set to path prefix
    """

    def rewrite_cookie(self, name, morsel):
        # if domain set, expand cookie to host prefix
        if morsel.get('domain'):
            del morsel['domain']
            morsel['path'] = self.url_rewriter.rewrite('/')

        # set cookie to rewritten path
        elif morsel.get('path'):
            morsel['path'] = self.url_rewriter.rewrite(morsel['path'])

        return morsel


#=================================================================
class ExactPathCookieRewriter(WbUrlBaseCookieRewriter):
    """
    Rewrite cookies only using exact path, useful for live rewrite
    without a timestamp and to minimize cookie pollution

    If path or domain present, simply remove
    """

    def rewrite_cookie(self, name, morsel):
        if morsel.get('domain'):
            del morsel['domain']
        # else set cookie to rewritten path
        if morsel.get('path'):
            del morsel['path']

        return morsel


#=================================================================
class RootScopeCookieRewriter(WbUrlBaseCookieRewriter):
    """
    Sometimes it is necessary to rewrite cookies to root scope
    in order to work across time boundaries and modifiers

    This rewriter simply sets all cookies to be in the root
    """
    def rewrite_cookie(self, name, morsel):
        # get root path
        morsel['path'] = self.url_rewriter.root_path

        # remove domain
        if morsel.get('domain'):
            del morsel['domain']

        return morsel


#=================================================================
def get_cookie_rewriter(cookie_scope):
    if cookie_scope == 'root':
        return RootScopeCookieRewriter
    elif cookie_scope == 'exact':
        return ExactPathCookieRewriter
    elif cookie_scope == 'host':
        return HostScopeCookieRewriter
    elif cookie_scope == 'removeall':
        return RemoveAllCookiesRewriter
    elif cookie_scope == 'coll':
        return MinimalScopeCookieRewriter
    else:
        return HostScopeCookieRewriter

# end pywb.rewrite.cookie_rewriter

# begin pywb.rewrite.header_rewriter

#=================================================================
class RewrittenStatusAndHeaders(object):
    def __init__(self, statusline, headers,
                 removed_header_dict, text_type, charset):

        self.status_headers = StatusAndHeaders(statusline, headers)
        self.removed_header_dict = removed_header_dict
        self.text_type = text_type
        self.charset = charset

    def contains_removed_header(self, name, value):
        return self.removed_header_dict.get(name) == value


#=================================================================
class HeaderRewriter(object):
    REWRITE_TYPES = {
        'html': ['text/html',
                 'application/xhtml',
                 'application/xhtml+xml'],

        'css':  ['text/css'],

        'js':   ['text/javascript',
                 'application/javascript',
                 'application/x-javascript'],

        'json': ['application/json'],

        'xml':  ['/xml', '+xml', '.xml', '.rss'],
    }

    PROXY_HEADERS = ['content-type', 'content-disposition', 'content-range',
                     'accept-ranges']

    URL_REWRITE_HEADERS = ['location', 'content-location', 'content-base']

    ENCODING_HEADERS = ['content-encoding']

    REMOVE_HEADERS = ['transfer-encoding', 'content-security-policy',
                      'strict-transport-security']

    PROXY_NO_REWRITE_HEADERS = ['content-length']

    COOKIE_HEADERS = ['set-cookie', 'cookie']

    CACHE_HEADERS = ['cache-control', 'expires', 'etag', 'last-modified']


    def __init__(self, header_prefix='X-Archive-Orig-'):
        self.header_prefix = header_prefix

    def rewrite(self, status_headers, urlrewriter, cookie_rewriter):
        content_type = status_headers.get_header('Content-Type')
        text_type = None
        charset = None
        strip_encoding = False
        http_cache = None
        if urlrewriter:
            http_cache = urlrewriter.rewrite_opts.get('http_cache')

        if content_type:
            text_type = self._extract_text_type(content_type)
            if text_type:
                charset = self._extract_char_set(content_type)
                strip_encoding = True

        result = self._rewrite_headers(status_headers.headers,
                                       urlrewriter,
                                       cookie_rewriter,
                                       strip_encoding,
                                       http_cache)

        new_headers = result[0]
        removed_header_dict = result[1]

        if http_cache != None and http_cache != 'pass':
            self._add_cache_headers(new_headers, http_cache)

        return RewrittenStatusAndHeaders(status_headers.statusline,
                                         new_headers,
                                         removed_header_dict,
                                         text_type,
                                         charset)

    def _add_cache_headers(self, new_headers, http_cache):
        try:
            age = int(http_cache)
        except:
            age = 0

        if age <= 0:
            new_headers.append(('Cache-Control', 'no-cache; no-store'))
        else:
            dt = datetime.utcnow()
            dt = dt + timedelta(seconds=age)
            new_headers.append(('Cache-Control', 'max-age=' + str(age)))
            new_headers.append(('Expires', datetime_to_http_date(dt)))

    def _extract_text_type(self, content_type):
        for ctype, mimelist in six.iteritems(self.REWRITE_TYPES):
            if any((mime in content_type) for mime in mimelist):
                return ctype

        return None

    def _extract_char_set(self, content_type):
        CHARSET_TOKEN = 'charset='
        idx = content_type.find(CHARSET_TOKEN)
        if idx < 0:
            return None

        return content_type[idx + len(CHARSET_TOKEN):].lower()

    def _rewrite_headers(self, headers, urlrewriter,
                         cookie_rewriter,
                         content_rewritten,
                         http_cache):

        new_headers = []
        removed_header_dict = {}

        def add_header(name, value):
            new_headers.append((name, value))

        def add_prefixed_header(name, value):
            new_headers.append((self.header_prefix + name, value))

        for (name, value) in headers:
            lowername = name.lower()

            if lowername in self.PROXY_HEADERS:
                add_header(name, value)

            elif urlrewriter and lowername in self.URL_REWRITE_HEADERS:
                new_headers.append((name, urlrewriter.rewrite(value)))

            elif lowername in self.ENCODING_HEADERS:
                if content_rewritten:
                    removed_header_dict[lowername] = value
                else:
                    add_header(name, value)

            elif lowername in self.REMOVE_HEADERS:
                removed_header_dict[lowername] = value
                add_prefixed_header(name, value)

            elif (lowername in self.PROXY_NO_REWRITE_HEADERS and
                  not content_rewritten):
                add_header(name, value)

            elif (lowername in self.COOKIE_HEADERS and
                  cookie_rewriter):
                cookie_list = cookie_rewriter.rewrite(value)
                new_headers.extend(cookie_list)

            elif (lowername in self.CACHE_HEADERS):
                if http_cache == 'pass':
                    add_header(name, value)
                else:
                    add_prefixed_header(name, value)

            elif urlrewriter:
                add_prefixed_header(name, value)
            else:
                add_header(name, value)

        return (new_headers, removed_header_dict)

# end  pywb.rewrite.header_rewriter

# begin pywb.rewrite.url_rewriter
#=================================================================
class UrlRewriter(object):
    """
    Main pywb UrlRewriter which rewrites absolute and relative urls
    to be relative to the current page, as specified via a WbUrl
    instance and an optional full path prefix
    """

    NO_REWRITE_URI_PREFIX = ('#', 'javascript:', 'data:',
                             'mailto:', 'about:', 'file:', '{')

    PROTOCOLS = ('http:', 'https:', 'ftp:', 'mms:', 'rtsp:', 'wais:')

    REL_SCHEME = ('//', r'\/\/', r'\\/\\/')

    def __init__(self, wburl, prefix='', full_prefix=None, rel_prefix=None,
                 root_path=None, cookie_scope=None, rewrite_opts=None):
        self.wburl = wburl if isinstance(wburl, WbUrl) else WbUrl(wburl)
        self.prefix = prefix
        self.full_prefix = full_prefix or prefix
        self.rel_prefix = rel_prefix or prefix
        self.root_path = root_path or '/'
        if self.full_prefix and self.full_prefix.startswith(self.PROTOCOLS):
            self.prefix_scheme = self.full_prefix.split(':')[0]
        else:
            self.prefix_scheme = None
        self.prefix_abs = self.prefix and self.prefix.startswith(self.PROTOCOLS)
        self.cookie_scope = cookie_scope
        self.rewrite_opts = rewrite_opts or {}

        if self.rewrite_opts.get('punycode_links'):
            self.wburl._do_percent_encode = False

    def rewrite(self, url, mod=None):
        # if special protocol, no rewriting at all
        if url.startswith(self.NO_REWRITE_URI_PREFIX):
            return url

        if (self.prefix and
             self.prefix != '/' and
             url.startswith(self.prefix)):
            return url

        if (self.full_prefix and
             self.full_prefix != self.prefix and
             url.startswith(self.full_prefix)):
            return url

        wburl = self.wburl

        is_abs = url.startswith(self.PROTOCOLS)

        scheme_rel = False
        if url.startswith(self.REL_SCHEME):
            is_abs = True
            scheme_rel = True
            # if prefix starts with a scheme
            #if self.prefix_scheme:
            #    url = self.prefix_scheme + ':' + url
            #url = 'http:' + url

        # optimize: join if not absolute url, otherwise just use as is
        if not is_abs:
            new_url = self.urljoin(wburl.url, url)
        else:
            new_url = url

        if mod is None:
            mod = wburl.mod

        final_url = self.prefix + wburl.to_str(mod=mod, url=new_url)

        if not is_abs and self.prefix_abs and not self.rewrite_opts.get('no_match_rel'):
            parts = final_url.split('/', 3)
            final_url = '/'
            if len(parts) == 4:
                final_url += parts[3]

        # experiment for setting scheme rel url
        elif scheme_rel and self.prefix_abs:
            final_url = final_url.split(':', 1)[1]

        return final_url

    def get_new_url(self, **kwargs):
        return self.prefix + self.wburl.to_str(**kwargs)

    def rebase_rewriter(self, new_url):
        if new_url.startswith(self.prefix):
            new_url = new_url[len(self.prefix):]
        elif new_url.startswith(self.rel_prefix):
            new_url = new_url[len(self.rel_prefix):]

        new_wburl = WbUrl(new_url)
        return self._create_rebased_rewriter(new_wburl, self.prefix)

    def _create_rebased_rewriter(self, new_wburl, prefix):
        return UrlRewriter(new_wburl, prefix)

    def get_cookie_rewriter(self, scope=None):
        # collection scope overrides rule scope?
        if self.cookie_scope:
            scope = self.cookie_scope

        cls = get_cookie_rewriter(scope)
        return cls(self)

    def deprefix_url(self):
        return self.wburl.deprefix_url(self.full_prefix)

    def __repr__(self):
        return "UrlRewriter('{0}', '{1}')".format(self.wburl, self.prefix)

    @staticmethod
    def urljoin(orig_url, url):  # pragma: no cover
        new_url = urljoin(orig_url, url)
        if '../' not in new_url:
            return new_url

        # only needed in py2 as py3 urljoin resolves '../'
        parts = urlsplit(new_url)
        scheme, netloc, path, query, frag = parts

        path_parts = path.split('/')
        i = 0
        n = len(path_parts) - 1
        while i < n:
            if path_parts[i] == '..':
                del path_parts[i]
                n -= 1
                if i > 0:
                    del path_parts[i - 1]
                    n -= 1
                    i -= 1
            else:
                i += 1

        if path_parts == ['']:
            path = '/'
        else:
            path = '/'.join(path_parts)

        parts = (scheme, netloc, path, query, frag)

        new_url = urlunsplit(parts)
        return new_url


#=================================================================
class SchemeOnlyUrlRewriter(UrlRewriter):
    """
    A url rewriter which ensures that any urls have the same
    scheme (http or https) as the base url.
    Other urls/input is unchanged.
    """

    def __init__(self, *args, **kwargs):
        super(SchemeOnlyUrlRewriter, self).__init__(*args, **kwargs)
        self.url_scheme = self.wburl.url.split(':')[0]
        if self.url_scheme == 'https':
            self.opposite_scheme = 'http'
        else:
            self.opposite_scheme = 'https'

    def rewrite(self, url, mod=None):
        if url.startswith(self.opposite_scheme + '://'):
            url = self.url_scheme + url[len(self.opposite_scheme):]

        return url

    def get_new_url(self, **kwargs):
        return kwargs.get('url', self.wburl.url)

    def rebase_rewriter(self, new_url):
        return self

    def get_cookie_rewriter(self, scope=None):
        return None

    def deprefix_url(self):
        return self.wburl.url

# end pywb.rewrite.url_rewriter

# begin pywb.framework.basehandlers
#=================================================================
class BaseHandler(object):
    """
    Represents a base handler class that handles any request
    """
    def __call__(self, wbrequest):  # pragma: no cover
        raise NotImplementedError('Need to implement in derived class')

    def get_wburl_type(self):
        return None


#=================================================================
class WbUrlHandler(BaseHandler):
    """
    Represents a handler which assumes the request contains a WbUrl
    Ensure that the WbUrl is parsed in the request
    """
    def get_wburl_type(self):
        return WbUrl
# end pywb.framework.basehandlers

# begin pywb.framework.cache
#=================================================================
class UwsgiCache(object):  # pragma: no cover
    def __setitem__(self, item, value):
        uwsgi.cache_update(item, value)

    def __getitem__(self, item):
        return uwsgi.cache_get(item)

    def __contains__(self, item):
        return uwsgi.cache_exists(item)

    def __delitem__(self, item):
        uwsgi.cache_del(item)


#=================================================================
class DefaultCache(dict):
    def __getitem__(self, item):
        return self.get(item)


#=================================================================
class RedisCache(object):
    def __init__(self, redis_url):
        # must be of the form redis://host:port/db/key
        redis_url, key = redis_url.rsplit('/', 1)
        self.redis = StrictRedis.from_url(redis_url)
        self.key = key

    def __setitem__(self, item, value):
        self.redis.hset(self.key, item, value)

    def __getitem__(self, item):
        return to_native_str(self.redis.hget(self.key, item), 'utf-8')

    def __contains__(self, item):
        return self.redis.hexists(self.key, item)

    def __delitem__(self, item):
        self.redis.hdel(self.key, item)


#=================================================================
def create_cache(redis_url_key=None):
    if redis_url_key:
        return RedisCache(redis_url_key)

    if uwsgi_cache:  # pragma: no cover
        return UwsgiCache()
    else:
        return De
# end pywb.framework.cache

# begin pywb.framework.archivalrouter

#=================================================================
# ArchivalRouter -- route WB requests in archival mode
#=================================================================
class ArchivalRouter(object):
    def __init__(self, routes, **kwargs):
        self.routes = routes

        # optional port setting may be ignored by wsgi container
        self.port = kwargs.get('port')

        self.fallback = ReferRedirect()

        self.abs_path = kwargs.get('abs_path')

        self.home_view = kwargs.get('home_view')
        self.error_view = kwargs.get('error_view')
        self.info_view = kwargs.get('info_view')

        config = kwargs.get('config', {})
        self.urlrewriter_class = config.get('urlrewriter_class', UrlRewriter)

        self.enable_coll_info = config.get('enable_coll_info', False)

    def __call__(self, env):
        request_uri = self.ensure_rel_uri_set(env)

        for route in self.routes:
            matcher, coll = route.is_handling(request_uri)
            if matcher:
                wbrequest = self.parse_request(route, env, matcher,
                                               coll, request_uri,
                                               use_abs_prefix=self.abs_path)

                return route.handler(wbrequest)

        # Default Home Page
        if request_uri in ['/', '/index.html', '/index.htm']:
            return self.render_home_page(env)

        if self.enable_coll_info and request_uri in ['/collinfo.json']:
            params = env.get('pywb.template_params', {})
            host = WbRequest.make_host_prefix(env)
            return self.info_view.render_response(env=env, host=host, routes=self.routes,
                                                  content_type='application/json',
                                                  **params)

        return self.fallback(env, self) if self.fallback else None

    def parse_request(self, route, env, matcher, coll, request_uri,
                      use_abs_prefix=False):
        matched_str = matcher.group(0)
        rel_prefix = env.get('SCRIPT_NAME', '') + '/'

        if matched_str:
            rel_prefix += matched_str + '/'
            # remove the '/' + rel_prefix part of uri
            wb_url_str = request_uri[len(matched_str) + 2:]
        else:
            # the request_uri is the wb_url, since no coll
            wb_url_str = request_uri[1:]

        wbrequest = route.request_class(env,
                              request_uri=request_uri,
                              wb_url_str=wb_url_str,
                              rel_prefix=rel_prefix,
                              coll=coll,
                              use_abs_prefix=use_abs_prefix,
                              wburl_class=route.handler.get_wburl_type(),
                              urlrewriter_class=self.urlrewriter_class,
                              cookie_scope=route.cookie_scope,
                              rewrite_opts=route.rewrite_opts,
                              user_metadata=route.user_metadata)

        # Allow for applying of additional filters
        route.apply_filters(wbrequest, matcher)

        return wbrequest

    def render_home_page(self, env):
        if self.home_view:
            params = env.get('pywb.template_params', {})
            return self.home_view.render_response(env=env, routes=self.routes, **params)
        else:
            return None

    #=================================================================
    # adapted from wsgiref.request_uri, but doesn't include domain name
    # and allows all characters which are allowed in the path segment
    # according to: http://tools.ietf.org/html/rfc3986#section-3.3
    # explained here:
    # http://stackoverflow.com/questions/4669692/
    #   valid-characters-for-directory-part-of-a-url-for-short-links

    @staticmethod
    def ensure_rel_uri_set(env):
        """ Return the full requested path, including the query string
        """
        if 'REL_REQUEST_URI' in env:
            return env['REL_REQUEST_URI']

        if not env.get('SCRIPT_NAME') and env.get('REQUEST_URI'):
            env['REL_REQUEST_URI'] = env['REQUEST_URI']
            return env['REL_REQUEST_URI']

        url = quote(env.get('PATH_INFO', ''), safe='/~!$&\'()*+,;=:@')
        query = env.get('QUERY_STRING')
        if query:
            url += '?' + query

        env['REL_REQUEST_URI'] = url
        return url


#=================================================================
# Route by matching regex (or fixed prefix)
# of request uri (excluding first '/')
#=================================================================
class Route(object):
    # match upto next / or ? or end
    SLASH_QUERY_LOOKAHEAD = '(?=/|$|\?)'

    def __init__(self, regex, handler, config=None,
                 request_class=WbRequest,
                 lookahead=SLASH_QUERY_LOOKAHEAD):

        config = config or {}
        self.path = regex
        if regex:
            self.regex = re.compile(regex + lookahead)
        else:
            self.regex = re.compile('')

        self.handler = handler
        self.request_class = request_class

        # collection id from regex group (default 0)
        self.coll_group = int(config.get('coll_group', 0))
        self.cookie_scope = config.get('cookie_scope')
        self.rewrite_opts = config.get('rewrite_opts', {})
        self.user_metadata = config.get('metadata', {})
        self._custom_init(config)

    def is_handling(self, request_uri):
        matcher = self.regex.match(request_uri[1:])
        if not matcher:
            return None, None

        coll = matcher.group(self.coll_group)
        return matcher, coll

    def apply_filters(self, wbrequest, matcher):
        for filter in self.filters:
            last_grp = len(matcher.groups())
            filter_str = filter.format(matcher.group(last_grp))
            wbrequest.query_filter.append(filter_str)

    def _custom_init(self, config):
        self.filters = config.get('filters', [])


#=================================================================
# ReferRedirect -- redirect urls that have 'fallen through'
# based on the referrer settings
#=================================================================
class ReferRedirect:
    def __call__(self, env, the_router):
        referrer = env.get('HTTP_REFERER')

        routes = the_router.routes

        # ensure there is a referrer
        if referrer is None:
            return None

        # get referrer path name
        ref_split = urlsplit(referrer)

        # require that referrer starts with current Host, if any
        curr_host = env.get('HTTP_HOST')
        if curr_host and curr_host != ref_split.netloc:
            return None

        path = ref_split.path

        app_path = env.get('SCRIPT_NAME', '')

        if app_path:
            # must start with current app name, if not root
            if not path.startswith(app_path):
                return None

            path = path[len(app_path):]

        ref_route = None
        ref_request = None

        for route in routes:
            matcher, coll = route.is_handling(path)
            if matcher:
                ref_request = the_router.parse_request(route, env,
                                                       matcher, coll, path)
                ref_route = route
                break

        # must have matched one of the routes with a urlrewriter
        if not ref_request or not ref_request.urlrewriter:
            return None

        rewriter = ref_request.urlrewriter

        rel_request_uri = env['REL_REQUEST_URI']

        timestamp_path = '/' + rewriter.wburl.timestamp + '/'

        # check if timestamp is already part of the path
        if rel_request_uri.startswith(timestamp_path):
            # remove timestamp but leave / to make host relative url
            # 2013/path.html -> /path.html
            rel_request_uri = rel_request_uri[len(timestamp_path) - 1:]

        rewritten_url = rewriter.rewrite(rel_request_uri)

        # if post, can't redirect as that would lost the post data
        # (can't use 307 because FF will show confirmation warning)
        if ref_request.method == 'POST':
            new_wb_url = WbUrl(rewritten_url[len(rewriter.prefix):])
            ref_request.wb_url.url = new_wb_url.url
            return ref_route.handler(ref_request)

        final_url = urlunsplit((ref_split.scheme,
                                ref_split.netloc,
                                rewritten_url,
                                '',
                                ''))

        return WbResponse.redir_response(final_url, status='302 Temp Redirect')

# end pywb.framework.archivalrouter


# begin pywb.framework.proxy_resolvers
#=================================================================
class BaseCollResolver(object):
    def __init__(self, routes, config):
        self.routes = routes
        self.use_default_coll = config.get('use_default_coll')

    @property
    def pre_connect(self):
        return False

    def resolve(self, env):
        route = None
        coll = None
        matcher = None
        ts = None

        proxy_coll, ts = self.get_proxy_coll_ts(env)

        # invalid parsing
        if proxy_coll == '':
            return None, None, None, None, self.select_coll_response(env, proxy_coll)

        if proxy_coll is None and isinstance(self.use_default_coll, str):
            proxy_coll = self.use_default_coll

        if proxy_coll:
            path = '/' + proxy_coll + '/'

            for r in self.routes:
                matcher, c = r.is_handling(path)
                if matcher:
                    route = r
                    coll = c
                    break

            # if no match, return coll selection response
            if not route:
                return None, None, None, None, self.select_coll_response(env, proxy_coll)

        # if 'use_default_coll', find first WbUrl-handling collection
        elif self.use_default_coll:
            raise Exception('use_default_coll: true no longer supported, please specify collection name')
            #for route in self.routes:
            #    if isinstance(route.handler, WbUrlHandler):
            #        return route, route.path, matcher, ts, None

        # otherwise, return the appropriate coll selection response
        else:
            return None, None, None, None, self.select_coll_response(env, proxy_coll)

        return route, coll, matcher, ts, None


#=================================================================
class ProxyAuthResolver(BaseCollResolver):
    DEFAULT_MSG = 'Please enter name of a collection to use with proxy mode'

    def __init__(self, routes, config):
        super(ProxyAuthResolver, self).__init__(routes, config)
        self.auth_msg = config.get('auth_msg', self.DEFAULT_MSG)

    @property
    def pre_connect(self):
        return True

    @property
    def supports_switching(self):
        return False

    def get_proxy_coll_ts(self, env):
        proxy_auth = env.get('HTTP_PROXY_AUTHORIZATION')

        if not proxy_auth:
            return None, None

        proxy_coll = self.read_basic_auth_coll(proxy_auth)
        return proxy_coll, None

    def select_coll_response(self, env, default_coll=None):
        proxy_msg = 'Basic realm="{0}"'.format(self.auth_msg)

        headers = [('Content-Type', 'text/plain'),
                   ('Proxy-Authenticate', proxy_msg)]

        status_headers = StatusAndHeaders('407 Proxy Authentication', headers)

        value = self.auth_msg

        return WbResponse(status_headers, value=[value.encode('utf-8')])

    @staticmethod
    def read_basic_auth_coll(value):
        parts = value.split(' ')
        if parts[0].lower() != 'basic':
            return ''

        if len(parts) != 2:
            return ''

        user_pass = base64.b64decode(parts[1].encode('utf-8'))
        return to_native_str(user_pass.split(b':')[0])


#=================================================================
class IPCacheResolver(BaseCollResolver):
    def __init__(self, routes, config):
        super(IPCacheResolver, self).__init__(routes, config)
        self.cache = create_cache(config.get('redis_cache_key'))
        self.magic_name = config['magic_name']

    @property
    def supports_switching(self):
        return False

    def _get_ip(self, env):
        ip = env['REMOTE_ADDR']
        qs = env.get('pywb.proxy_query')
        if qs:
            res = parse_qs(qs)

            if 'ip' in res:
                ip = res['ip'][0]

        return ip

    def select_coll_response(self, env, default_coll=None):
        raise WbException('Invalid Proxy Collection Specified: ' + str(default_coll))

    def get_proxy_coll_ts(self, env):
        ip = env['REMOTE_ADDR']
        qs = env.get('pywb.proxy_query')

        if qs:
            res = parse_qs(qs)

            if 'ip' in res:
                ip = res['ip'][0]

            if 'delete' in res:
                del self.cache[ip + ':c']
                del self.cache[ip + ':t']
            else:
                if 'coll' in res:
                    self.cache[ip + ':c'] = res['coll'][0]

                if 'ts' in res:
                    self.cache[ip + ':t'] = res['ts'][0]

        coll = self.cache[ip + ':c']
        ts = self.cache[ip + ':t']
        return coll, ts

    def resolve(self, env):
        server_name = env['pywb.proxy_host']

        if self.magic_name in server_name:
            response = self.handle_magic_page(env)
            if response:
                return None, None, None, None, response

        return super(IPCacheResolver, self).resolve(env)

    def handle_magic_page(self, env):
        coll, ts = self.get_proxy_coll_ts(env)
        ip = self._get_ip(env)
        res = json.dumps({'ip': ip, 'coll': coll, 'ts': ts})
        return WbResponse.text_response(res, content_type='application/json')


#=================================================================
class CookieResolver(BaseCollResolver):
    SESH_COOKIE_NAME = '__pywb_proxy_sesh'

    def __init__(self, routes, config):
        super(CookieResolver, self).__init__(routes, config)
        self.magic_name = config['magic_name']
        self.sethost_prefix = '-sethost.' + self.magic_name + '.'
        self.set_prefix = '-set.' + self.magic_name

        self.cookie_name = config.get('cookie_name', self.SESH_COOKIE_NAME)
        self.proxy_select_view = config.get('proxy_select_view')

        self.extra_headers = config.get('extra_headers')

        self.cache = create_cache()

    @property
    def supports_switching(self):
        return True

    def get_proxy_coll_ts(self, env):
        coll, ts, sesh_id = self.get_coll(env)
        return coll, ts

    def select_coll_response(self, env, default_coll=None):
        return self.make_magic_response('auto',
                                        env['REL_REQUEST_URI'],
                                        env)

    def resolve(self, env):
        server_name = env['pywb.proxy_host']

        if ('.' + self.magic_name) in server_name:
            response = self.handle_magic_page(env)
            if response:
                return None, None, None, None, response

        return super(CookieResolver, self).resolve(env)

    def handle_magic_page(self, env):
        request_url = env['REL_REQUEST_URI']
        parts = urlsplit(request_url)
        server_name = env['pywb.proxy_host']

        path_url = parts.path[1:]
        if parts.query:
            path_url += '?' + parts.query

        if server_name.startswith('auto'):
            coll, ts, sesh_id = self.get_coll(env)

            if coll:
                return self.make_sethost_cookie_response(sesh_id,
                                                         path_url,
                                                         env)
            else:
                return self.make_magic_response('select', path_url, env)

        elif server_name.startswith('query.'):
            wb_url = WbUrl(path_url)

            # only dealing with specific timestamp setting
            if wb_url.is_query():
                return None

            coll, ts, sesh_id = self.get_coll(env)
            if not coll:
                return self.make_magic_response('select', path_url, env)

            self.set_ts(sesh_id, wb_url.timestamp)
            return self.make_redir_response(wb_url.url)

        elif server_name.endswith(self.set_prefix):
            old_sesh_id = extract_client_cookie(env, self.cookie_name)
            sesh_id = self.create_renew_sesh_id(old_sesh_id)

            if sesh_id != old_sesh_id:
                headers = self.make_cookie_headers(sesh_id, self.magic_name)
            else:
                headers = None

            coll = server_name[:-len(self.set_prefix)]

            # set sesh value
            self.set_coll(sesh_id, coll)

            return self.make_sethost_cookie_response(sesh_id, path_url, env,
                                                     headers=headers)

        elif self.sethost_prefix in server_name:
            inx = server_name.find(self.sethost_prefix)
            sesh_id = server_name[:inx]

            domain = server_name[inx + len(self.sethost_prefix):]

            headers = self.make_cookie_headers(sesh_id, domain)

            full_url = env['pywb.proxy_scheme'] + '://' + domain
            full_url += '/' + path_url
            return self.make_redir_response(full_url, headers=headers)

        elif 'select.' in server_name:
            coll, ts, sesh_id = self.get_coll(env)

            route_temp = '-set.' + self.magic_name + '/' + path_url

            return (self.proxy_select_view.
                    render_response(routes=self.routes,
                                    route_temp=route_temp,
                                    coll=coll,
                                    url=path_url))
        #else:
        #    msg = 'Invalid Magic Path: ' + url
        #    print msg
        #    return WbResponse.text_response(msg, status='404 Not Found')

    def make_cookie_headers(self, sesh_id, domain):
        cookie_val = '{0}={1}; Path=/; Domain=.{2}; HttpOnly'
        cookie_val = cookie_val.format(self.cookie_name, sesh_id, domain)
        headers = [('Set-Cookie', cookie_val)]
        return headers

    def make_sethost_cookie_response(self, sesh_id, path_url,
                                     env, headers=None):
        if '://' not in path_url:
            path_url = 'http://' + path_url

        path_parts = urlsplit(path_url)

        new_url = path_parts.path[1:]
        if path_parts.query:
            new_url += '?' + path_parts.query

        return self.make_magic_response(sesh_id + '-sethost', new_url, env,
                                        suffix=path_parts.netloc,
                                        headers=headers)

    def make_magic_response(self, prefix, url, env,
                            suffix=None, headers=None):
        full_url = env['pywb.proxy_scheme'] + '://' + prefix + '.'
        full_url += self.magic_name
        if suffix:
            full_url += '.' + suffix
        full_url += '/' + url
        return self.make_redir_response(full_url, headers=headers)

    def set_coll(self, sesh_id, coll):
        self.cache[sesh_id + ':c'] = coll

    def set_ts(self, sesh_id, ts):
        if ts:
            self.cache[sesh_id + ':t'] = ts
        # this ensures that omitting timestamp will reset to latest
        # capture by deleting the cache entry
        else:
            del self.cache[sesh_id + ':t']

    def get_coll(self, env):
        sesh_id = extract_client_cookie(env, self.cookie_name)

        coll = None
        ts = None
        if sesh_id:
            coll = self.cache[sesh_id + ':c']
            ts = self.cache[sesh_id + ':t']

        return coll, ts, sesh_id

    def create_renew_sesh_id(self, sesh_id, force=False):
        #if sesh_id in self.cache and not force:
        if sesh_id and ((sesh_id + ':c') in self.cache) and not force:
            return sesh_id

        sesh_id = base64.b32encode(os.urandom(5)).lower()
        return to_native_str(sesh_id)

    def make_redir_response(self, url, headers=None):
        if not headers:
            headers = []

        if self.extra_headers:
            for name, value in six.iteritems(self.extra_headers):
                headers.append((name, value))

        return WbResponse.redir_response(url, headers=headers)

# end pywb.framework.proxy_resolvers


# begin pywb.framework.memento
#=================================================================
class MementoReqMixin(object):
    def _parse_extra(self):
        if not self.wb_url:
            return

        if self.wb_url.type != self.wb_url.LATEST_REPLAY:
            return

        self.options['is_timegate'] = True

        accept_datetime = self.env.get('HTTP_ACCEPT_DATETIME')
        if not accept_datetime:
            return

        try:
            timestamp = http_date_to_timestamp(accept_datetime)
        except Exception:
            raise BadRequestException('Invalid Accept-Datetime: ' +
                                      accept_datetime)

        # note: this changes from LATEST_REPLAY -> REPLAY
        self.wb_url.set_replay_timestamp(timestamp)


#=================================================================
class MementoRequest(MementoReqMixin, WbRequest):
    pass


#=================================================================
class MementoRespMixin(object):
    def _init_derived(self, params):
        wbrequest = params.get('wbrequest')
        is_redirect = params.get('memento_is_redir', False)
        cdx = params.get('cdx')

        if not wbrequest or not wbrequest.wb_url:
            return

        mod = wbrequest.options.get('replay_mod', '')

        #is_top_frame = wbrequest.wb_url.is_top_frame
        is_top_frame = wbrequest.options.get('is_top_frame', False)

        is_timegate = (wbrequest.options.get('is_timegate', False) and
                       not is_top_frame)

        if is_timegate:
            self.status_headers.headers.append(('Vary', 'accept-datetime'))

        # Determine if memento:
        is_memento = False
        is_original = False

        # if no cdx included, not a memento, unless top-frame special
        if not cdx:
            # special case: include the headers but except Memento-Datetime
            # since this is really an intermediate resource
            if is_top_frame:
                is_memento = True

        # otherwise, if in proxy mode, then always a memento
        elif wbrequest.options['is_proxy']:
            is_memento = True
            is_original = True

        # otherwise only if timestamp replay (and not a timegate)
        #elif not is_timegate:
        #    is_memento = (wbrequest.wb_url.type == wbrequest.wb_url.REPLAY)
        elif not is_redirect:
            is_memento = (wbrequest.wb_url.is_replay())

        link = []
        req_url = wbrequest.wb_url.url

        if is_memento or is_timegate:
            url = req_url
            if cdx:
                ts = cdx['timestamp']
                url = cdx['url']
            # for top frame
            elif wbrequest.wb_url.timestamp:
                ts = wbrequest.wb_url.timestamp
            else:
                ts = None

            if ts:
                http_date = timestamp_to_http_date(ts)

                if is_memento:
                    self.status_headers.headers.append(('Memento-Datetime',
                                                       http_date))

                canon_link = wbrequest.urlrewriter.get_new_url(mod=mod,
                                                               timestamp=ts,
                                                               url=url)

                # set in replay_views -- Must set content location
                #if is_memento and is_timegate:
                #    self.status_headers.headers.append(('Content-Location',
                #                                        canon_link))

                # don't set memento link for very long urls...
                if len(canon_link) < 512:
                    link.append(self.make_memento_link(canon_link,
                                                       'memento',
                                                       http_date))

        if is_original and is_timegate:
            link.append(self.make_link(req_url, 'original timegate'))
        else:
            link.append(self.make_link(req_url, 'original'))

        # for now, include timemap only in non-proxy mode
        if not wbrequest.options['is_proxy'] and (is_memento or is_timegate):
            link.append(self.make_timemap_link(wbrequest))

        if is_memento and not is_timegate:
            timegate = wbrequest.urlrewriter.get_new_url(mod=mod, timestamp='')
            link.append(self.make_link(timegate, 'timegate'))

        link = ', '.join(link)

        self.status_headers.headers.append(('Link', link))

    def make_link(self, url, type):
        return '<{0}>; rel="{1}"'.format(url, type)

    def make_memento_link(self, url, type_, dt):
        return '<{0}>; rel="{1}"; datetime="{2}"'.format(url, type_, dt)

    def make_timemap_link(self, wbrequest):
        format_ = '<{0}>; rel="timemap"; type="{1}"'

        url = wbrequest.urlrewriter.get_new_url(mod='timemap',
                                                timestamp='',
                                                type=wbrequest.wb_url.QUERY)

        return format_.format(url, LINK_FORMAT)


#=================================================================
class MementoResponse(MementoRespMixin, WbResponse):
    pass


#=================================================================
def make_timemap_memento_link(cdx, prefix, datetime=None,
                             rel='memento', end=',\n', mod=''):

    memento = '<{0}>; rel="{1}"; datetime="{2}"' + end

    string = WbUrl.to_wburl_str(url=cdx['url'],
                                mod=mod,
                                timestamp=cdx['timestamp'],
                                type=WbUrl.REPLAY)

    url = prefix + string

    if not datetime:
        datetime = timestamp_to_http_date(cdx['timestamp'])

    return memento.format(url, rel, datetime)


#=================================================================
def make_timemap(wbrequest, cdx_lines):
    prefix = wbrequest.wb_prefix
    url = wbrequest.wb_url.url
    mod = wbrequest.options.get('replay_mod', '')

    # get first memento as it'll be used for 'from' field
    try:
        first_cdx = six.next(cdx_lines)
        from_date = timestamp_to_http_date(first_cdx['timestamp'])
    except StopIteration:
        first_cdx = None


    if first_cdx:
        # timemap link
        timemap = ('<{0}>; rel="self"; ' +
                   'type="application/link-format"; from="{1}",\n')
        yield timemap.format(prefix + wbrequest.wb_url.to_str(),
                             from_date)

    # original link
    original = '<{0}>; rel="original",\n'
    yield original.format(url)

    # timegate link
    timegate = '<{0}>; rel="timegate",\n'
    timegate_url= WbUrl.to_wburl_str(url=url,
                                     mod=mod,
                                     type=WbUrl.LATEST_REPLAY)

    yield timegate.format(prefix + timegate_url)

    if not first_cdx:
        # terminating timemap link, no from
        timemap = ('<{0}>; rel="self"; type="application/link-format"')
        yield timemap.format(prefix + wbrequest.wb_url.to_str())
        return

    # first memento link
    yield make_timemap_memento_link(first_cdx, prefix,
                            datetime=from_date, mod=mod)

    prev_cdx = None

    for cdx in cdx_lines:
        if prev_cdx:
            yield make_timemap_memento_link(prev_cdx, prefix, mod=mod)

        prev_cdx = cdx

    # last memento link, if any
    if prev_cdx:
        yield make_timemap_memento_link(prev_cdx, prefix, end='', mod=mod)

# end pywb.framework.memento


# begin pywb.webapp.views
#=================================================================
class template_filter(object):
    """
    Decorator for registering a function as a jinja2 filter
    If optional argument is supplied, it is used as the filter name
    Otherwise, the func name is the filter name
    """
    def __init__(self, param=None):
        self.name = param

    def __call__(self, func):
        name = self.name
        if not name:
            name = func.__name__

        FILTERS[name] = func
        return func


#=================================================================
# Filters
@template_filter()
def format_ts(value, format_='%a, %b %d %Y %H:%M:%S'):
    if format_ == '%s':
        return timestamp_to_sec(value)
    else:
        value = timestamp_to_datetime(value)
        return value.strftime(format_)


@template_filter('urlsplit')
def get_urlsplit(url):
    split = urlsplit(url)
    return split


@template_filter()
def is_wb_handler(obj):
    if not hasattr(obj, 'handler'):
        return False

    return obj.handler.__class__.__name__ == "WBHandler"


@template_filter()
def tojson(obj):
    return json.dumps(obj)


#=================================================================
class FileOnlyPackageLoader(PackageLoader):
    def get_source(self, env, template):
        dir_, file_ = os.path.split(template)
        return super(FileOnlyPackageLoader, self).get_source(env, file_)


#=================================================================
class RelEnvironment(Environment):
    """Override join_path() to enable relative template paths."""
    def join_path(self, template, parent):
        return os.path.join(os.path.dirname(parent), template)


#=================================================================
class J2TemplateView(object):
    shared_jinja_env = None

    def __init__(self, filename):
        self.template_file = filename
        self.jinja_env = self.init_shared_env()

    @staticmethod
    def init_shared_env(paths=['templates', '.', '/'],
                        packages=['pywb'],
                        overlay_env=None):

        if J2TemplateView.shared_jinja_env:
            return J2TemplateView.shared_jinja_env

        loaders = J2TemplateView._add_loaders(paths, packages)
        loader = ChoiceLoader(loaders)

        if overlay_env:
            jinja_env = overlay_env.overlay(loader=loader, trim_blocks=True)
        else:
            jinja_env = RelEnvironment(loader=loader, trim_blocks=True)

        jinja_env.filters.update(FILTERS)
        J2TemplateView.shared_jinja_env = jinja_env
        return jinja_env

    @staticmethod
    def _add_loaders(paths, packages):
        loaders = []
        # add loaders for paths
        for path in paths:
            loaders.append(FileSystemLoader(path))

        # add loaders for all specified packages
        for package in packages:
            loaders.append(FileOnlyPackageLoader(package))

        return loaders

    def render_to_string(self, **kwargs):
        template = self.jinja_env.get_template(self.template_file)

        wbrequest = kwargs.get('wbrequest')
        if wbrequest:
            params = wbrequest.env.get('pywb.template_params')
            if params:
                kwargs.update(params)

        template_result = template.render(**kwargs)

        return template_result

    def render_response(self, **kwargs):
        template_result = self.render_to_string(**kwargs)
        status = kwargs.get('status', '200 OK')
        content_type = kwargs.get('content_type', 'text/html; charset=utf-8')
        return WbResponse.text_response(template_result,
                                        status=status,
                                        content_type=content_type)


#=================================================================
def init_view(config, key, view_class=J2TemplateView):
    filename = config.get(key)
    if not filename:
        return None

    logging.debug('Adding {0}: {1}'.format(key, filename))
    return view_class(filename)


#=================================================================
class HeadInsertView(J2TemplateView):
    def create_insert_func(self, wbrequest,
                           include_ts=True):

        if wbrequest.options['is_ajax']:
            return None

        url = wbrequest.wb_url.get_url()

        top_url = wbrequest.wb_prefix
        top_url += wbrequest.wb_url.to_str(mod=wbrequest.final_mod)

        include_wombat = not wbrequest.wb_url.is_banner_only

        def make_head_insert(rule, cdx):
            cdx['url'] = url
            return (self.render_to_string(wbrequest=wbrequest,
                                          cdx=cdx,
                                          top_url=top_url,
                                          include_ts=include_ts,
                                          include_wombat=include_wombat,
                                          banner_html=self.banner_html,
                                          rule=rule))
        return make_head_insert

    @staticmethod
    def init_from_config(config):
        view = config.get('head_insert_view')
        if not view:
            html = config.get('head_insert_html', 'templates/head_insert.html')

            if html:
                banner_html = config.get('banner_html', 'banner.html')
                view = HeadInsertView(html)
                logging.debug('Adding HeadInsert: {0}, Banner {1}'.
                              format(html, banner_html))

                view.banner_html = banner_html

        return view


#=================================================================
# query views
#=================================================================
class J2HtmlCapturesView(J2TemplateView):
    def render_response(self, wbrequest, cdx_lines, **kwargs):
        def format_cdx_lines():
            for cdx in cdx_lines:
                cdx['_orig_url'] = cdx['url']
                cdx['url'] = wbrequest.wb_url.get_url(url=cdx['url'])
                yield cdx

        return J2TemplateView.render_response(self,
                                    cdx_lines=list(format_cdx_lines()),
                                    url=wbrequest.wb_url.get_url(),
                                    type=wbrequest.wb_url.type,
                                    prefix=wbrequest.wb_prefix,
                                    **kwargs)


#=================================================================
class MementoTimemapView(object):
    def render_response(self, wbrequest, cdx_lines, **kwargs):
        memento_lines = make_timemap(wbrequest, cdx_lines)

        return WbResponse.text_stream(memento_lines,
                                      content_type=LINK_FORMAT)


# end pywb.webapp.views


# bgin pywb.framework.wsgi_wrappers
#=================================================================
class WSGIApp(object):
    def __init__(self, wb_router, fallback_app=None):
        self.wb_router = wb_router
        self.fallback_app = fallback_app

    # Top-level wsgi application
    def __call__(self, env, start_response):
        if env['REQUEST_METHOD'] == 'CONNECT':
            return self.handle_connect(env, start_response)
        else:
            return self.handle_methods(env, start_response)

    def handle_connect(self, env, start_response):
        def ssl_start_response(statusline, headers):
            ssl_sock = env.get('pywb.proxy_ssl_sock')
            if not ssl_sock:
                start_response(statusline, headers)
                return

            env['pywb.proxy_statusline'] = statusline

            status_line = 'HTTP/1.1 ' + statusline + '\r\n'
            ssl_sock.write(status_line.encode('iso-8859-1'))

            for name, value in headers:
                line = name + ': ' + value + '\r\n'
                ssl_sock.write(line.encode('iso-8859-1'))

        resp_iter = self.handle_methods(env, ssl_start_response)

        ssl_sock = env.get('pywb.proxy_ssl_sock')
        if not ssl_sock:
            return resp_iter

        ssl_sock.write(b'\r\n')

        for obj in resp_iter:
            if obj:
                ssl_sock.write(obj)
        ssl_sock.close()

        start_response(env['pywb.proxy_statusline'], [])

        return []

    def handle_methods(self, env, start_response):
        wb_router = self.wb_router
        response = None

        try:
            response = wb_router(env)

            if not response:
                if self.fallback_app:
                    return self.fallback_app(env, start_response)
                else:
                    msg = 'No handler for "{0}".'.format(env['REL_REQUEST_URI'])
                    raise NotFoundException(msg)

        except WbException as e:
            response = self.handle_exception(env, e, False)

        except Exception as e:
            response = self.handle_exception(env, e, True)

        return response(env, start_response)

    def handle_exception(self, env, exc, print_trace):
        error_view = None

        if hasattr(self.wb_router, 'error_view'):
            error_view = self.wb_router.error_view

        if hasattr(exc, 'status'):
            status = exc.status()
        else:
            status = '500 Internal Server Error'

        if hasattr(exc, 'url'):
            err_url = exc.url
        else:
            err_url = None

        if len(exc.args):
            err_msg = exc.args[0]

        if print_trace:
            import traceback
            err_details = traceback.format_exc()
            print(err_details)
        else:
            logging.info(err_msg)
            err_details = None

        if error_view:
            if err_url and isinstance(err_url, str):
                err_url = to_native_str(err_url, 'utf-8')
            if err_msg and isinstance(err_msg, str):
                err_msg = to_native_str(err_msg, 'utf-8')

            return error_view.render_response(exc_type=type(exc).__name__,
                                              err_msg=err_msg,
                                              err_details=err_details,
                                              status=status,
                                              env=env,
                                              err_url=err_url)
        else:
            msg = status + ' Error: '
            if err_msg:
                msg += err_msg

            #msg = msg.encode('utf-8', 'ignore')
            return WbResponse.text_response(msg,
                                           status=status)


#=================================================================
def init_app(init_func, load_yaml=True, config_file=None, config=None):
    logging.basicConfig(format='%(asctime)s: [%(levelname)s]: %(message)s',
                        level=logging.DEBUG)
    logging.debug('')

    try:
        config = config or {}
        if load_yaml:
            # env setting overrides all others
            env_config = os.environ.get('PYWB_CONFIG_FILE')
            if env_config:
                config_file = env_config

            if not config_file:
                config_file = DEFAULT_CONFIG_FILE

            if os.path.isfile(config_file):
                config = load_yaml_config(config_file)

        wb_router = init_func(config)
    except:
        msg = '*** pywb app init FAILED config from "%s"!\n'
        logging.exception(msg, init_func.__name__)
        raise
    else:
        msg = '*** pywb app inited with config from "%s"!\n'
        logging.debug(msg, init_func.__name__)

    return WSGIApp(wb_router)


#=================================================================
def start_wsgi_ref_server(the_app, name, port):  # pragma: no cover
    from wsgiref.simple_server import make_server, WSGIServer
    from six.moves.socketserver import ThreadingMixIn

    # disable is_hop_by_hop restrictions
    import wsgiref.handlers
    wsgiref.handlers.is_hop_by_hop = lambda x: False

    if port is None:
        port = DEFAULT_PORT

    logging.info('Starting %s on port %s', name, port)

    class ThreadingWSGIServer(ThreadingMixIn, WSGIServer):
        pass

    try:
        httpd = make_server('', port, the_app, ThreadingWSGIServer)
        httpd.serve_forever()
    except KeyboardInterrupt as ex:
        pass
    finally:
        logging.info('Stopping %s', name)

# end pywb.framework.wsgi_wrappers

#=================================================================
# init pywb app
#=================================================================

BlockLoader.init_default_loaders()

application = init_app(create_wb_router, load_yaml=True)
