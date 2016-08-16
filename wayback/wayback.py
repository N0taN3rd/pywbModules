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
import zlib
import pprint

from distutils.util import strtobool
from pkg_resources import resource_string

from argparse import ArgumentParser, RawTextHelpFormatter

from six.moves.urllib.parse import urlencode, quote
from six.moves.urllib.parse import parse_qs
from six.moves.urllib.request import pathname2url, url2pathname
from six.moves.urllib.parse import urljoin, unquote_plus, urlsplit
import six.moves.urllib.parse as urlparse
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

DEFAULT_PORT = 8080

WRAP_WIDTH = 80

FILTERS = {}

#=================================================================
DEFAULT_CONFIG_FILE = 'config.yaml'

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
