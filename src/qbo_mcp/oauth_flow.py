import logging
import ssl
import threading
import time
import webbrowser
from http.server import BaseHTTPRequestHandler, HTTPServer
from pathlib import Path
from urllib.parse import urlparse, parse_qs

logger = logging.getLogger(__name__)

CERTS_DIR = Path(__file__).resolve().parent.parent.parent / "certs"


def run_interactive_oauth(auth_client, scopes):
    """
    Run the interactive OAuth flow: start a local HTTPS server, open browser,
    capture code/realmId, exchange for tokens.
    Returns a dict: {access_token, refresh_token, environment, realm_id}
    """
    class OAuthHandler(BaseHTTPRequestHandler):
        server_version = "OAuthHandler/0.1"
        code = None
        realm_id = None
        error = None
        def do_GET(self):
            parsed = urlparse(self.path)
            params = parse_qs(parsed.query)
            if 'code' in params and 'realmId' in params and parsed.path == '/callback':
                OAuthHandler.code = params['code'][0]
                OAuthHandler.realm_id = params['realmId'][0]
                self.send_response(200)
                self.send_header('Content-type', 'text/html')
                self.end_headers()
                self.wfile.write(b"<html><body><h1>Authentication successful. You may close this window.</h1></body></html>")
            elif 'error' in params:
                OAuthHandler.error = params['error'][0]
                self.send_response(400)
                self.end_headers()
                self.wfile.write(b"<html><body><h1>Authentication failed.</h1></body></html>")
            else:
                self.send_response(400)
                self.end_headers()
                self.wfile.write(b"<html><body><h1>Invalid request.</h1></body></html>")
        def log_message(self, format, *args):
            logger.debug(format % args)

    redirect_uri = auth_client.redirect_uri
    parsed_uri = urlparse(redirect_uri)
    host = parsed_uri.hostname or 'localhost'
    port = parsed_uri.port or 8001
    use_https = parsed_uri.scheme == 'https'

    httpd = HTTPServer((host, port), OAuthHandler)

    if use_https:
        cert_file = CERTS_DIR / "localhost.crt"
        key_file = CERTS_DIR / "localhost.key"
        if not cert_file.exists() or not key_file.exists():
            raise FileNotFoundError(
                f"SSL certs not found at {CERTS_DIR}. "
                "Run: openssl req -x509 -newkey rsa:2048 "
                "-keyout certs/localhost.key -out certs/localhost.crt "
                "-days 3650 -nodes -subj '/CN=localhost'"
            )
        ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        ctx.load_cert_chain(certfile=str(cert_file), keyfile=str(key_file))
        httpd.socket = ctx.wrap_socket(httpd.socket, server_side=True)
        logger.info(f"Started local OAuth 2.0 HTTPS server at https://{host}:{port}")
    else:
        logger.info(f"Started local OAuth 2.0 HTTP server at http://{host}:{port}")

    server_thread = threading.Thread(target=httpd.serve_forever)
    server_thread.daemon = True
    server_thread.start()

    try:
        auth_url = auth_client.get_authorization_url(scopes=scopes)
    except Exception as e:
        logger.error(f"Error getting authorization URL: {str(e)}")
        httpd.shutdown()
        server_thread.join()
        raise
    logger.info(f"\nPlease open the following URL in your browser to authorize the application:\n{auth_url}\n")
    webbrowser.open(auth_url, 2, True)
    logger.info("Waiting for user to complete OAuth flow...")

    while OAuthHandler.code is None and OAuthHandler.error is None:
        time.sleep(0.5)
    httpd.shutdown()
    server_thread.join()
    if OAuthHandler.error:
        logger.error(f"OAuth error: {OAuthHandler.error}")
        raise RuntimeError(f"OAuth error: {OAuthHandler.error}")
    if not OAuthHandler.code or not OAuthHandler.realm_id:
        logger.error("Did not receive code and realmId from OAuth redirect.")
        raise RuntimeError("Did not receive code and realmId from OAuth redirect.")
    try:
        auth_client.get_bearer_token(OAuthHandler.code, OAuthHandler.realm_id)
        tokens = {
            'access_token': auth_client.access_token,
            'refresh_token': auth_client.refresh_token,
            'environment': auth_client.environment,
            'realm_id': auth_client.realm_id,
        }
        logger.info("Successfully obtained tokens from OAuth flow.")
        return tokens
    except Exception as e:
        logger.error(f"Failed to exchange code for tokens: {str(e)}")
        raise 