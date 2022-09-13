"""Constants"""

from datetime import timedelta
from typing import Literal

Protocol = Literal[b'Negotiate', b'NTLM']

DEFAULT_PROTOCOL: Protocol = b'Negotiate'
DEFAULT_SERVICE = 'HTTP'
DEFAULT_SESSION_DURATION = timedelta(hours=1)

SSPI_CONTEXT_KEY = 'sspi'
