# bareASGI-sspi

ASGI middleware for the bareASGI framework providing SSPI authentication on Windows.

## Installation

Install from the pie store.

```
pip install bareasgi-sspi
```

## Usage

The following program uses the
[Hypercorn](https://pgjones.gitlab.io/hypercorn/)
ASGI server, and the
[bareASGI](https://github.com/rob-blackbourn/bareASGI)
ASGI framework.

```python
import asyncio
import logging
from typing import Optional

from bareasgi import Application, HttpRequest, HttpResponse
from bareutils import text_writer
from hypercorn import Config
from hypercorn.asyncio import serve

from bareasgi_sspi import SPNEGOMiddleware, SSPIDetails

# A callback to display the results of the SSPI middleware.
async def http_request_callback(request: HttpRequest) -> HttpResponse:
    # Get the details from the request context request['sspi']. Note if
    # authentication failed this might be absent or empty.
    sspi: Optional[SSPIDetails] = request.context.get('sspi')
    client_principal = (
        sspi['client_principal']
        if sspi is not None
        else 'unknown'
    )
    return HttpResponse(
        200,
        [(b'content-type', b'text/plain')],
        text_writer(f"Authenticated as '{client_principal}'")
    )


async def main_async():
    # Create the middleware. Change the protocol from Negotiate to NTLM,
    # and allow unauthenticated requests to pass through.
    sspi_middleware = SPNEGOMiddleware(
        protocol=b'NTLM',
        forbid_unauthenticated=False
    )

    # Make the ASGI application using the middleware.
    app = Application(middlewares=[sspi_middleware])
    app.http_router.add({'GET'}, '/', http_request_callback)

    # Start the ASGI server.
    config = Config()
    config.bind = ['localhost:9023']
    await serve(app, config)

if __name__ == '__main__':
    logging.basicConfig(level=logging.DEBUG)
    asyncio.run(main_async())
```

### Arguments

Optional arguments include:

* `protocol` (`bytes`): Either `b"Negotiate"` or `b"NTLM"`.
* `service` (`str`): The SPN service. Defaults to `"HTTP"`.
* `hostname` (`str`, optional): The hostname. Defaults to he result of `socket.gethostname()`.
* `service_principal` (`str`, optional): The service principal.
* `session_duration` (`timedelta`, optional): The duration of a session. Defaults to 1 hour.
* `forbid_unauthenticated` (`bool`): If true, and authentication fails, send 403 (Forbidden). Otherwise handle the request unauthenticated.
* `context_key` (`str`, optional): The key used in the request context. Defaults to `sspi`.

If `service_principal` if specified, it supersedes `service` and `hostname`.

### Results

If the authentication is successful the SSPI details are added to the
`context` dictionary of the HttpRequest object with the key `"sspi"`.

The following properties are set:

* `"client_principal"` (`str`): The username of the client.
* `"negotiated_protocol"` (`str`): The negotiated protocol.
* `"protocol"` (`str`): The requested protocol.
* `"spn"` (`str`): The SPN of the server.
