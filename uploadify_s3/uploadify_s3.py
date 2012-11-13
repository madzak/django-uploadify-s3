from django.conf import settings
from django.core.exceptions import ImproperlyConfigured
from urllib import quote_plus
from datetime import datetime
from datetime import timedelta
import base64
import hmac, sha
import json

UPLOADIFY_OPTIONS = ('auto', 'buttonClass', 'buttonCursor', 'buttonImage', 'buttonText',
'checkExisting', 'debug', 'fileObjName', 'fileSizeLimit', 'fileTypeDesc', 'fileTypeExts',
'formData', 'height', 'method', 'multi', 'overrideEvents', 'preventCaching', 'progressData',
'queueID', 'queueSizeLimit', 'removeCompleted', 'removeTimeout', 'requeueErrors',
'successTimeout', 'swf', 'uploader', 'uploadLimit', 'width')

UPLOADIFY_METHODS = ('onCancel', 'onClearQueue', 'onDestroy', 'onDialogClose', 'onDialogOpen',
'onDisable', 'onEnable', 'onFallback', 'onInit', 'onQueueComplete', 'onSelect', 'onSelectError',
'onSWFReady', 'onUploadComplete', 'onUploadError', 'onUploadProgress', 'onUploadStart',
'onUploadSuccess')

PASS_THRU_OPTIONS = ('folder', 'fileExt',)
FILTERED_KEYS  = ('Filename', 'key',)
EXCLUDED_KEYS     = ('AWSAccessKeyId', 'policy', 'signature',)

# AWS Options
ACCESS_KEY_ID       = getattr(settings, 'UPLOADIFY_AWS_ACCESS_KEY_ID', None)
SECRET_ACCESS_KEY   = getattr(settings, 'UPLOADIFY_AWS_SECRET_ACCESS_KEY', None)
BUCKET_NAME         = getattr(settings, 'UPLOADIFY_AWS_BUCKET_NAME', None)
SECURE_URLS         = getattr(settings, 'UPLOADIFY_AWS_S3_SECURE_URLS', True)
BUCKET_URL          = getattr(settings, 'UPLOADIFY_AWS_BUCKET_URL', ('https://' if SECURE_URLS else 'http://') + BUCKET_NAME + '.s3.amazonaws.com')
DEFAULT_ACL         = getattr(settings, 'UPLOADIFY_AWS_DEFAULT_ACL', 'private')
DEFAULT_KEY_PATTERN = getattr(settings, 'UPLOADIFY_AWS_DEFAULT_KEY_PATTERN', '${filename}')
DEFAULT_FORM_TIME   = getattr(settings, 'UPLOADIFY_AWS_DEFAULT_FORM_LIFETIME', 36000) # 10 HOURS

# Defaults for required Uploadify options
DEFAULT_SWF  = settings.STATIC_URL + "uploadify/uploadify.swf"

class UploadifyS3(object):
    """Uploadify for Amazon S3"""
    
    def __init__(self, uploadify_options={}, post_data={}, conditions={}):
        self.options = getattr(settings, 'UPLOADIFY_DEFAULT_OPTIONS', {})
        self.options.update(uploadify_options)
        
        for key in self.options:
            if key not in (UPLOADIFY_OPTIONS + UPLOADIFY_METHODS):
                raise ImproperlyConfigured("Attempted to initialize with unrecognized option '%s'." % key)

        _set_default_if_none(self.options, 'swf', DEFAULT_SWF)
        _set_default_if_none(self.options, 'uploader', BUCKET_URL)

        self.post_data = post_data
        _set_default_if_none(self.post_data, 'key', DEFAULT_KEY_PATTERN)
        _set_default_if_none(self.post_data, 'acl', DEFAULT_ACL)
        
        try:
            _set_default_if_none(self.post_data, 'bucket', BUCKET_NAME)
        except ValueError:
            raise ImproperlyConfigured("Bucket name is a required property.")
 
        try:
            _set_default_if_none(self.post_data, 'AWSAccessKeyId', _uri_encode(ACCESS_KEY_ID))
        except ValueError:
            raise ImproperlyConfigured("AWS Access Key ID is a required property.")

        self.conditions = build_conditions(self.options, self.post_data, conditions)

        if not SECRET_ACCESS_KEY:
            raise ImproperlyConfigured("AWS Secret Access Key is a required property.")
        
        expiration_time = datetime.utcnow() + timedelta(seconds=DEFAULT_FORM_TIME)
        self.policy_string = build_post_policy(expiration_time, self.conditions)
        self.policy = base64.b64encode(self.policy_string)
         
        self.signature = base64.encodestring(hmac.new(SECRET_ACCESS_KEY, self.policy, sha).digest()).strip()
        
        self.post_data['policy'] = self.policy
        self.post_data['signature'] = self.signature
        self.options['formData'] = self.post_data
        self.options['debug'] = settings.DEBUG
        self.options['fileObjName'] = 'file'
        
    def get_options_json(self):
        # return json.dumps(self.options)
        
        subs = []
        for key in self.options:
            if key in UPLOADIFY_METHODS:
                subs.append(('"%%%s%%"' % key, self.options[key]))
                self.options[key] = "%%%s%%" % key
                
        out = json.dumps(self.options)
        
        for search, replace in subs:
            out = out.replace(search, replace)
            
        return out

def build_conditions(options, post_data, conditions):
    # PASS_THRU_OPTIONS are Uploadify options that if set in the settings are 
    # passed into the POST. As a result, a default policy condition is created here.
    for opt in PASS_THRU_OPTIONS:
        if opt in options and opt not in conditions:
            conditions[opt] = None

    # FILTERED_KEYS are those created by Uploadify and passed into the POST on submit.
    # As a result, a default policy condition is created here.
    for opt in FILTERED_KEYS:
        if opt not in conditions:
            conditions[opt] = None

    conds = post_data.copy()
    conds.update(conditions)

    # EXCLUDED_KEYS are those that are set by UploadifyS3 but need to be stripped out
    # for the purposes of creating conditions.
    for key in EXCLUDED_KEYS:
        if key in conds:
            del conds[key]

    return conds

def build_post_policy(expiration_time, conditions):
    """ Function to build S3 POST policy. Adapted from Programming Amazon Web Services, Murty, pg 104-105. """
    conds = []
    for name, test in conditions.iteritems():
        if test is None:
            # A None condition value means allow anything.
            conds.append('["starts-with", "$%s", ""]' % name)
        elif isinstance(test,str) or isinstance(test, unicode):
            conds.append('{"%s": "%s" }' % (name, test))
        elif isinstance(test,list):
            conds.append('{"%s": "%s" }' % (name, ','.join(test)))
        elif isinstance(test, dict):
            operation = test['op']
            value = test['value']
            conds.append('["%s", "$%s", "%s"]' % (operation, name, value))
        elif isinstance(test,slice):
            conds.append('["%s", "%s", "%s"]' %(name, test.start, test.stop))
        else:
            raise TypeError("Unexpected value type for condition '%s': %s" % (name, type(test)))

    return '{"expiration": "%s", "conditions": [%s]}' \
            % (expiration_time.strftime("%Y-%m-%dT%H:%M:%SZ"), ', '.join(conds))
            
def _uri_encode(str):
    try:
        # The Uploadify flash component apparently decodes the formData once, so we need to encode twice here.
        return quote_plus(quote_plus(str, safe='~'), safe='~')
    except:
        raise ValueError

def _set_default_if_none(dict, key, default=None):
    if key not in dict:
        if default:
            dict[key] = default
        else:
            raise ValueError

    
