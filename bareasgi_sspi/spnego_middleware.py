"""Middleware for SSPI using spnego"""

import base64
from datetime import datetime, timedelta
import logging
import socket
from typing import (
    List,
    Literal,
    Optional,
    Tuple,
    TypedDict,
    cast
)

from asgi_typing import (
    Scope,
    HTTPScope,
    ASGIReceiveCallable,
    ASGISendCallable,
    ASGIHTTPReceiveCallable,
    ASGIHTTPSendCallable,
    ASGI3Application
)
from bareutils import header, response_code
import spnego

from .session_manager import SessionManager, Session

LOGGER = logging.getLogger(__name__)


class SSPIDetails(TypedDict):
    """The details available from SPNEGO"""
    client_principal: str
    negotiated_protocol: str
    protocol: str
    spn: str


class SSPISession(Session):
    """The data to store for a session"""
    server_auth: spnego.ContextProxy
    status: Optional[Literal['requested', 'accepted', 'rejected']]
    sspi: Optional[SSPIDetails]


class SPNEGOSessionManager(SessionManager[SSPISession]):
    """The session manager implementation for SPNEGO"""

    def __init__(
            self,
            session_duration: timedelta,
            hostname: str,
            service: str,
            protocol: str
    ) -> None:
        super().__init__(session_duration)
        self.hostname = hostname
        self.service = service
        self.protocol = protocol

    def create_session(self, expiry: datetime) -> SSPISession:
        server_auth = spnego.server(
            hostname=self.hostname,
            service=self.service,
            protocol=self.protocol.lower()
        )

        session: SSPISession = {
            'server_auth': server_auth,
            'expiry': expiry,
            'status': None,
            'sspi': None
        }

        return session


class SPNEGOMiddleware:
    """ASGI middleware for authenticating with SSPI using SPNEGO

    Authentication data is stored in the scope `"extensions"` property under
    `"sspi"`.
    """

    def __init__(
            self,
            app: ASGI3Application,
            *,
            protocol: Literal[b'Negotiate', b'NTLM'] = b'Negotiate',
            service: str = 'HTTP',
            hostname: Optional[str] = None,
            service_principal: Optional[str] = None,
            session_duration: timedelta = timedelta(hours=1),
            forbid_unauthenticated: bool = True
    ) -> None:
        self._app = app
        self.protocol = protocol
        self.forbid_unauthenticated = forbid_unauthenticated

        if service_principal is not None:
            service, hostname = service_principal.split('@')
        elif hostname is None:
            hostname = socket.gethostname()

        self._session_manager = SPNEGOSessionManager(
            session_duration,
            hostname,
            service,
            self.protocol.decode('ascii')
        )

    async def _send_response(
            self,
            send: ASGIHTTPSendCallable,
            status: int,
            headers: List[Tuple[bytes, bytes]],
            body: bytes
    ) -> None:
        await send({
            'type': 'http.response.start',
            'status': status,
            'headers': [
                (b'content-type', b'text/plain'),
                (b'content-length', str(len(body)).encode('ascii')),
                *headers
            ]
        })
        await send({
            'type': 'http.response.body',
            'body': body,
            'more_body': False
        })

    async def _send_forbidden(self, send: ASGIHTTPSendCallable) -> None:
        await self._send_response(
            send,
            response_code.FORBIDDEN,
            [],
            b'Forbidden'
        )

    async def _handle_request(
            self,
            session: SSPISession,
            scope: HTTPScope,
            receive: ASGIHTTPReceiveCallable,
            send: ASGIHTTPSendCallable
    ) -> None:
        scope['extensions']['sspi'] = session['sspi']  # type: ignore
        await self._app(
            cast(Scope, scope),
            cast(ASGIReceiveCallable, receive),
            cast(ASGISendCallable, send)
        )

    async def _request_authentication(
            self,
            session: SSPISession,
            headers: List[Tuple[bytes, bytes]],
            scope: HTTPScope,
            send: ASGIHTTPSendCallable
    ) -> None:
        LOGGER.debug(
            "Requesting authentication for client %s using %s",
            scope['client'],
            self.protocol
        )
        body = b'Unauthenticated'
        await self._send_response(
            send,
            response_code.UNAUTHORIZED,
            [
                (b'www-authenticate', self.protocol),
                (b'content-type', b'text/plain'),
                (b'content-length', str(len(body)).encode('ascii')),
                * headers
            ],
            body
        )
        session['status'] = 'requested'

    async def _authenticate(
            self,
            authorization: Optional[bytes],
            session: SSPISession,
            scope: HTTPScope,
            receive: ASGIHTTPReceiveCallable,
            send: ASGIHTTPSendCallable
    ) -> None:
        if not authorization:
            raise Exception("Missing 'authorization' header")

        in_token = base64.b64decode(authorization[len(self.protocol)+1:])
        server_auth = session['server_auth']
        buf = server_auth.step(in_token)

        if server_auth.complete:
            LOGGER.debug(
                "Authentication succeeded for client %s using %s as user %s",
                scope['client'],
                self.protocol,
                server_auth.client_principal
            )
            session['status'] = 'accepted'
            session['sspi'] = {
                'client_principal': server_auth.client_principal,
                'protocol': server_auth.protocol,
                'negotiated_protocol': server_auth.negotiated_protocol,
                'spn': server_auth.spn
            }
            await self._handle_request(session, scope, receive, send)
            return

        if buf:
            LOGGER.debug(
                "Sending challenge for client %s using %s",
                scope['client'],
                self.protocol
            )
            out_token = self.protocol + b" " + base64.b64encode(buf)
            body = b'Unauthorized'
            await self._send_response(
                send,
                response_code.UNAUTHORIZED,
                [
                    (b'www-authenticate', out_token),
                    (b'content-type', b'text/plain'),
                    (b'content-length', str(len(body)).encode('ascii'))
                ],
                body
            )
            return

        raise Exception("Handshake failed")

    async def _process_authentication(
            self,
            session: SSPISession,
            scope: HTTPScope,
            receive: ASGIHTTPReceiveCallable,
            send: ASGIHTTPSendCallable
    ) -> None:
        authorization = header.find(b'authorization', scope['headers'])
        try:
            await self._authenticate(
                authorization,
                session,
                scope,
                receive,
                send
            )
        except:  # pylint: disable=bare-except
            LOGGER.exception(
                "Failed to authenticate for client %s using %s",
                scope['client'],
                self.protocol
            )
            session['status'] = 'rejected'
            await self._handle_rejected(session, scope, receive, send)

    async def _handle_rejected(
            self,
            session: SSPISession,
            scope: HTTPScope,
            receive: ASGIHTTPReceiveCallable,
            send: ASGIHTTPSendCallable
    ) -> None:
        if self.forbid_unauthenticated:
            self._send_forbidden(send)
        else:
            self._handle_request(session, scope, receive, send)

    async def _send_internal_server_error(
            self,
            scope: HTTPScope,
            send: ASGIHTTPSendCallable
    ) -> None:
        LOGGER.debug(
            "Failed to handle message for client %s",
            scope['client']
        )
        body = b'Internal Server Error'
        await self._send_response(
            send,
            response_code.INTERNAL_SERVER_ERROR,
            [
                (b'content-type', b'text/plain'),
                (b'content-length', str(len(body)).encode('ascii'))
            ],
            body
        )

    async def _process_http(
            self,
            scope: HTTPScope,
            receive: ASGIHTTPReceiveCallable,
            send: ASGIHTTPSendCallable
    ) -> None:
        session, headers = self._session_manager.get_session(scope)

        if session['status'] is None:
            await self._request_authentication(session, headers, scope, send)
        elif session['status'] == 'requested':
            await self._process_authentication(session, scope, receive, send)
        elif session['status'] == 'accepted':
            await self._handle_request(session, scope, receive, send)
        elif session['status'] == 'rejected':
            await self._handle_rejected(session, scope, receive, send)
        else:
            await self._send_internal_server_error(scope, send)

    async def __call__(
            self,
            scope: Scope,
            receive: ASGIReceiveCallable,
            send: ASGISendCallable
    ) -> None:
        if scope['type'] != 'http':
            await self._app(scope, receive, send)
        else:
            await self._process_http(
                cast(HTTPScope, scope),
                cast(ASGIHTTPReceiveCallable, receive),
                cast(ASGIHTTPSendCallable, send)
            )
