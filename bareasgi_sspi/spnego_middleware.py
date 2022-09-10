"""Middleware for SSPI using spnego"""

import base64
from datetime import datetime, timedelta, timezone
import logging
import secrets
import socket
from typing import (
    Dict,
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
from bareutils import encode_set_cookie, header, response_code
import spnego

LOGGER = logging.getLogger(__name__)


class SSPIDetails(TypedDict):
    client_principal: str
    negotiated_protocol: str
    protocol: str
    spn: str


class SSPISession(TypedDict):
    server_auth: spnego.ContextProxy
    status: Optional[Literal['requested', 'accepted', 'rejected']]
    expiry: datetime
    sspi: Optional[SSPIDetails]


class SPNEGOMiddleware:

    def __init__(
            self,
            app: ASGI3Application,
            *,
            auth_type: Literal[b'Negotiate', b'NTLM'] = b'Negotiate',
            service: str = 'HTTP',
            hostname: Optional[str] = None,
            service_principal: Optional[str] = None,
            session_duration: timedelta = timedelta(hours=1),
            forbid_unauthenticated: bool = True
    ) -> None:
        self.app = app
        self.sessions: Dict[bytes, SSPISession] = {}
        self.session_cookie_name = secrets.token_urlsafe().encode('ascii')
        self.auth_type = auth_type
        self.session_duration = session_duration
        self.forbid_unauthenticated = forbid_unauthenticated

        if service_principal is not None:
            self._service_name, self._hostname = service_principal.split('@')
        else:
            self._service_name = service
            self._hostname = hostname if hostname is not None else socket.gethostname()

    def _get_session_key_from_cookie(
        self,
        scope: HTTPScope
    ) -> Optional[bytes]:
        cookies = header.cookie(scope['headers'])
        session_cookie = cookies.get(self.session_cookie_name)
        if not session_cookie:
            return None

        return session_cookie[0]

    def _make_new_session_key(self) -> bytes:
        return secrets.token_hex(32).encode('ascii')

    def _make_session(self, now: datetime) -> Tuple[SSPISession, bytes]:
        session_key = self._make_new_session_key()

        server_auth = spnego.server(
            hostname=self._hostname,
            service=self._service_name,
            protocol=self.auth_type.decode('ascii').lower()
        )
        expiry = now + self.session_duration
        session: SSPISession = {
            'server_auth': server_auth,
            'expiry': expiry,
            'status': None,
            'sspi': None
        }

        set_cookie = encode_set_cookie(
            self.session_cookie_name,
            session_key,
            expires=expiry
        )

        return session, set_cookie

    def _get_session(
            self,
            scope: HTTPScope
    ) -> Tuple[SSPISession, List[Tuple[bytes, bytes]]]:
        session_key = self._get_session_key_from_cookie(scope)
        headers: List[Tuple[bytes, bytes]] = []

        now = datetime.now(timezone.utc)
        session = (
            self.sessions.get(session_key)
            if session_key is not None
            else None
        )
        if session is None or session['expiry'] < now:
            session, set_cookie = self._make_session(now)
            headers.append((b'set-cookie', set_cookie))

        return session, headers

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
        await self.app(
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
            self.auth_type
        )
        body = b'Unauthenticated'
        await self._send_response(
            send,
            response_code.UNAUTHORIZED,
            [
                (b'www-authenticate', self.auth_type),
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

        in_token = base64.b64decode(authorization[len(self.auth_type)+1:])
        server_auth = session['server_auth']
        buf = server_auth.step(in_token)

        if server_auth.complete:
            LOGGER.debug(
                "Authentication succeeded for client %s using %s as user %s",
                scope['client'],
                self.auth_type,
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
                self.auth_type
            )
            out_token = self.auth_type + b" " + base64.b64encode(buf)
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
                self.auth_type
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
        session, headers = self._get_session(scope)

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
            await self.app(scope, receive, send)
        else:
            await self._process_http(
                cast(HTTPScope, scope),
                cast(ASGIHTTPReceiveCallable, receive),
                cast(ASGIHTTPSendCallable, send)
            )
