from ..production import *

import json
import os

SECRET_KEY = "KWCU5WcQ1C6Rqn90uL2M"
ALLOWED_HOSTS = [
    "ecommerce.local.overhang.io",
    "ecommerce",
]
PLATFORM_NAME = "My Open edX"
PROTOCOL = "http"

CORS_ALLOW_CREDENTIALS = True

OSCAR_DEFAULT_CURRENCY = "USD"

EDX_API_KEY = "mQU7MekCkNyVP9sThbsY"

JWT_AUTH["JWT_ISSUER"] = "http://local.overhang.io/oauth2"
JWT_AUTH["JWT_AUDIENCE"] = "openedx"
JWT_AUTH["JWT_SECRET_KEY"] = "fBcv2PGoWag0GflYj49dPPPV"
JWT_AUTH["JWT_PUBLIC_SIGNING_JWK_SET"] = json.dumps(
    {
        "keys": [
            {
                "kid": "openedx",
                "kty": "RSA",
                "e": "AQAB",
                "n": "qFMhxHgsu1CTt67ibBa3tGyCg0tJbUhsfz-wEp2h1BvXO3mk19zB94NUQ1c0aWWapfwmau0e9hdsoYCxji4m2WGHuve1ytnIkfAdPX7RPkx_W3HMLep_9ASgTDvFbWBH5D83Sxfs-_dwEO5JzfX7ZJKi4OmmsmOKxG2_18prYyRFE8IeQX8TPtvSLPd_jqv9V36KiePfhPyadmavWCKIeD9CpWA4X8sWTtefasHjHWM9_gL5NKIt7ZUCrilDUb32oNHoJZZpA_G8b3e3MJwlHzgN9h2j0zREYeGxm2nJtOnZUg3uv1RkWKmOQxkOlaHJIEMlwWrlyY4iZoz6tBwYbw",
            }
        ]
    }
)
JWT_AUTH["JWT_ISSUERS"] = [
    {
        "ISSUER": "http://local.overhang.io/oauth2",
        "AUDIENCE": "openedx",
        "SECRET_KEY": "fBcv2PGoWag0GflYj49dPPPV"
    }
]

SOCIAL_AUTH_REDIRECT_IS_HTTPS = False
SOCIAL_AUTH_EDX_OAUTH2_ISSUER = "http://local.overhang.io"
SOCIAL_AUTH_EDX_OAUTH2_URL_ROOT = "http://lms:8000"

BACKEND_SERVICE_EDX_OAUTH2_SECRET = "wfVo2ntt"
BACKEND_SERVICE_EDX_OAUTH2_PROVIDER_URL = "http://lms:8000/oauth2"

EDX_DRF_EXTENSIONS = {
    'OAUTH2_USER_INFO_URL': 'http://local.overhang.io/oauth2/user_info',
}

DATABASES = {
    "default": {
        "ENGINE": "django.db.backends.mysql",
        "NAME": "ecommerce",
        "USER": "ecommerce",
        "PASSWORD": "BvSfvbDc",
        "HOST": "mysql",
        "PORT": "3306",
        "OPTIONS": {
            "init_command": "SET sql_mode='STRICT_TRANS_TABLES'",
        },
    }
}

EMAIL_BACKEND = "django.core.mail.backends.smtp.EmailBackend"
EMAIL_HOST = "smtp.gmail.com"
EMAIL_PORT = "587"
EMAIL_HOST_USER = "yogeshbhagat42code@gmail.com"
EMAIL_HOST_PASSWORD = "fqlwwdyqwdenbacw"
EMAIL_USE_TLS = True

ENTERPRISE_SERVICE_URL = 'http://local.overhang.io/enterprise/'
ENTERPRISE_API_URL = urljoin(ENTERPRISE_SERVICE_URL, 'api/v1/')

# Get rid of local logger
LOGGING["handlers"].pop("local")
for logger in LOGGING["loggers"].values():
    logger["handlers"].remove("local")

# Load payment processors
with open(
    os.path.join(os.path.dirname(__file__), "paymentprocessors.json"),
    encoding="utf8"
) as payment_processors_file:
    common_payment_processor_config = json.load(payment_processors_file)

# Fix cybersource-rest configuration
if "cybersource" in common_payment_processor_config and "cybersource-rest" not in common_payment_processor_config:
    common_payment_processor_config["cybersource-rest"] = common_payment_processor_config["cybersource"]
PAYMENT_PROCESSOR_CONFIG = {
    "openedx": common_payment_processor_config,
    "dev": common_payment_processor_config,
}
# Dummy config is required to bypass a KeyError
PAYMENT_PROCESSOR_CONFIG["edx"] = {
    "stripe": {
        "secret_key": "",
        "webhook_endpoint_secret": "",
    }
}
PAYMENT_PROCESSORS = list(PAYMENT_PROCESSORS) + []





CORS_ORIGIN_WHITELIST = list(CORS_ORIGIN_WHITELIST) + [
    "http://apps.local.overhang.io",
]
CSRF_TRUSTED_ORIGINS = ["apps.local.overhang.io"]

SOCIAL_AUTH_EDX_OAUTH2_PUBLIC_URL_ROOT = "http://local.overhang.io"

BACKEND_SERVICE_EDX_OAUTH2_KEY = "ecommerce"

