"""bareASGI middleware for SSPI using spnego"""

import base64
from datetime import datetime, timedelta
import logging
import socket
from typing import (
    List,
    Literal,
    Optional,
    Tuple,
    TypedDict
)

from bareasgi import HttpRequest, HttpRequestCallback, HttpResponse
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
            *,
            protocol: Literal[b'Negotiate', b'NTLM'] = b'Negotiate',
            service: str = 'HTTP',
            hostname: Optional[str] = None,
            session_duration: timedelta = timedelta(hours=1),
            forbid_unauthenticated: bool = True,
            context_key: str = 'sspi'
    ) -> None:
        """Initialise the SPNEGO middleware.

        Args:
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
        """
        self.protocol = protocol
        self.forbid_unauthenticated = forbid_unauthenticated
        self.context_key = context_key

        if hostname is None:
            hostname = socket.gethostname()

        self._session_manager = SPNEGOSessionManager(
            session_duration,
            hostname,
            service,
            self.protocol.decode('ascii')
        )

    def _forbidden(self) -> HttpResponse:
        return HttpResponse.from_text(
            'Forbidden',
            status=response_code.FORBIDDEN
        )

    def _unauthorized(self, headers: List[Tuple[bytes, bytes]]) -> HttpResponse:
        return HttpResponse.from_text(
            "Unauthorized",
            headers=headers,
            status=response_code.UNAUTHORIZED
        )

    async def _handle_accepted(
            self,
            session: SSPISession,
            request: HttpRequest,
            handler: HttpRequestCallback
    ) -> HttpResponse:
        # Store the result of the authentication in the request context.
        request.context[self.context_key] = session['sspi']
        return await handler(request)

    def _request_authentication(
            self,
            session: SSPISession,
            headers: List[Tuple[bytes, bytes]],
            request: HttpRequest
    ) -> HttpResponse:
        LOGGER.debug(
            "Requesting authentication for client %s using %s",
            request.scope['client'],
            self.protocol
        )

        # To request authentication a message with status 401 (Unauthorized)
        # is sent with the "www-authenticate" header set to the desired
        # protocol (e.g. Negotiate or NTLM). The client will then respond with
        # a message containing the "authorization" header. This header will
        # return the auth-scheme that the client has chosen, and a token.
        session['status'] = 'requested'
        return self._unauthorized([
            (b'www-authenticate', self.protocol),
            *headers
        ])

    async def _authenticate(
            self,
            authorization: Optional[bytes],
            session: SSPISession,
            request: HttpRequest,
            handler: HttpRequestCallback
    ) -> HttpResponse:
        # The authentication handshake involves an exchange of tokens.

        if not authorization:
            raise RuntimeError("Missing 'authorization' header")

        # Feed the client token into the authenticator. This is a two step
        # process.
        in_token = base64.b64decode(authorization[len(self.protocol)+1:])
        server_auth = session['server_auth']
        buf = server_auth.step(in_token)

        if server_auth.complete:
            # This is the second step. The handshake has succeeded and the
            # request can be passed on to the downstream handlers.
            LOGGER.debug(
                "Authentication succeeded for client %s using %s as user %s",
                request.scope['client'],
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
            return await self._handle_accepted(session, request, handler)

        if buf:
            # This is the first step. The client has sent an acceptable token
            # and the server responds with its own as another 401 response.
            LOGGER.debug(
                "Sending challenge for client %s using %s",
                request.scope['client'],
                self.protocol
            )
            out_token = self.protocol + b" " + base64.b64encode(buf)
            return self._unauthorized([(b'www-authenticate', out_token)])

        raise RuntimeError("Handshake failed")

    async def _handle_requested(
            self,
            session: SSPISession,
            request: HttpRequest,
            handler: HttpRequestCallback
    ) -> HttpResponse:
        authorization = header.find(b'authorization', request.scope['headers'])
        try:
            return await self._authenticate(
                authorization,
                session,
                request,
                handler
            )
        except:  # pylint: disable=bare-except
            LOGGER.exception(
                "Failed to authenticate for client %s using %s",
                request.scope['client'],
                self.protocol
            )
            session['status'] = 'rejected'
            return await self._handle_rejected(session, request, handler)

    async def _handle_rejected(
            self,
            session: SSPISession,
            request: HttpRequest,
            handler: HttpRequestCallback
    ) -> HttpResponse:
        if self.forbid_unauthenticated:
            return self._forbidden()
        else:
            return await self._handle_accepted(session, request, handler)

    async def __call__(
            self,
            request: HttpRequest,
            handler: HttpRequestCallback
    ) -> HttpResponse:
        try:
            session, headers = self._session_manager.get_session(request)

            if session['status'] is None:
                return self._request_authentication(session, headers, request)
            elif session['status'] == 'requested':
                return await self._handle_requested(session, request, handler)
            elif session['status'] == 'accepted':
                return await self._handle_accepted(session, request, handler)
            elif session['status'] == 'rejected':
                return await self._handle_rejected(session, request, handler)
            else:
                raise RuntimeError("Unhandled session status")

        except:  # pylint: disable=bare-except
            LOGGER.exception("Failed to authenticate")
            return HttpResponse.from_text(
                "Internal Server Error",
                status=response_code.INTERNAL_SERVER_ERROR,
            )
