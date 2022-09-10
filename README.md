# bareASGI-sspi

ASGI middleware for SSPI authentication on Windows.

## Installation

Install from the pie store.

```
pip install bareasgi-sspi
```

## Usage

The following program demonstrates the usage.

```python
import asyncio
import logging
from typing import cast, Optional

from bareasgi import Application, HttpRequest, HttpResponse
from bareutils import text_writer
from hypercorn import Config
from hypercorn.asyncio import serve

from bareasgi_sspi.spnego_middleware import SPNEGOMiddleware, SSPIDetails

async def http_request_callback(request: HttpRequest) -> HttpResponse:
    extensions = request.scope['extensions'] or {}
    sspi_details = cast(Optional[SSPIDetails], extensions.get('sspi'))
    client_principal = (
        sspi_details['client_principal']
        if sspi_details is not None
        else 'unknown'
    )
    return HttpResponse(
        200,
        [(b'content-type', b'text/plain')],
        text_writer(f"Authenticated as '{client_principal}'")
    )

async def main_async():
    app = Application()
    app.http_router.add({'GET'}, '/', http_request_callback)

    wrapped_app = SPNEGOMiddleware(
        app,
        protocol=b'NTLM',  # NTLM or Negotiate
        forbid_unauthenticated=True
    )

    config = Config()
    config.bind = ['localhost:9023']
    await serve(wrapped_app, config)

if __name__ == '__main__':
    logging.basicConfig(level=logging.DEBUG)
    asyncio.run(main_async())
```

The `SPNEGOMiddleware` wraps the ASGI application. Optional arguments include:

* `protocol` (`bytes`): Either `b"Negotiate"` or `b"NTLM"`.
* `service` (`str`): The SPN service. Defaults to `"HTTP"`.
* `hostname` (`str`, optional): The hostname. Defaults to `gethostname`.
* `service_principal` (`str`, optional): The service principal.
* `session_duration` (`timedelta`, optional): The duration of a session. Defaults to 1 hour.
* `forbid_unauthenticated` (`bool`): If true, and authentication fails, send 403 (Forbidden). Otherwise handle the request unauthenticated.

If the authentication is successful the SSPI details are added to the
`"extensions"` property of the ASGI scope under the property `"sspi"`.
The following properties are set:

* `"client_principal"` (`str`): The username of the client.
* `"negotiated_protocol"` (`str`): The negotiated protocol.
* `"protocol"` (`str`): The requested protocol.
* `"spn"` (`str`): The SPN of the server.
