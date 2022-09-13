"""Helpers"""

from datetime import timedelta
from typing import Optional

from bareasgi import Application, HttpRequest

from .constants import (
    Protocol,
    DEFAULT_PROTOCOL,
    SSPI_CONTEXT_KEY,
    DEFAULT_SERVICE,
    DEFAULT_SESSION_DURATION
)
from .spnego_middleware import SPNEGOMiddleware, SSPIDetails


def add_sspi_middleware(
    app: Application,
    *,
    protocol: Protocol = DEFAULT_PROTOCOL,
    service: str = DEFAULT_SERVICE,
    hostname: Optional[str] = None,
    session_duration: timedelta = DEFAULT_SESSION_DURATION,
    forbid_unauthenticated: bool = True,
    context_key: str = SSPI_CONTEXT_KEY
) -> Application:
    """Add SSPI middleware.

    Args:
        app (Application): A bareASGI application.
        protocol (Literal[b&#39;Negotiate&#39;, b&#39;NTLM&#39;], optional):
            The protocol. Defaults to b'Negotiate'.
        service (str, optional): The service. Defaults to 'HTTP'.
        hostname (Optional[str], optional): The hostname. Defaults to None.
        session_duration (timedelta, optional): The duration of a session
            before re-authentication is performed. Defaults to
            `timedelta(hours=1)`.
        forbid_unauthenticated (bool, optional): If true, 403 (Forbidden) is
            sent if authentication fails. If false the request is handled,
            but no authentication details are added. Defaults to True.
        context_key (str, optional): The name of the key that will be used
            to store the data in the HttpRequest context.
            Defaults to 'sspi'.

    Returns:
        Application: The ASGI application.
    """
    sspi_middleware = SPNEGOMiddleware(
        protocol=protocol,
        service=service,
        hostname=hostname,
        session_duration=session_duration,
        forbid_unauthenticated=forbid_unauthenticated,
        context_key=context_key
    )

    app.middlewares.append(sspi_middleware)

    return app


def sspi_details(
        request: HttpRequest,
        *,
        context_key: str = SSPI_CONTEXT_KEY
) -> Optional[SSPIDetails]:
    """Get the SSPI details from the HTTP request object.

    Args:
        request (HttpRequest): An HTTP request.
        context_key (str, optional): The context key. Defaults to SSPI_CONTEXT_KEY.

    Returns:
        Optional[SSPIDetails]: The SSPI details, if any.
    """
    return request.context[context_key]
