"""Example using the SPNEGO middleware"""

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
