import base64
import time
import ujson
import hashlib
import uuid
import pytest
from unittest.mock import Mock, patch, MagicMock
from cryptography.fernet import Fernet
from iris_relay.app import IDPInitiated, SAMLInitiate, get_relay_app, MAX_LOGIN_SESSIONS
from falcon import testing
import falcon


def minimal_test_config():
    return {
        'access_ttl': 3600,
        'refresh_ttl': 86400,
        'redirect_url': 'iris://auth',
        'encrypt_key': Fernet.generate_key().decode('utf-8'),
        'saml_encryption': False,
        'allow_origins_list': ['http://localhost'],
        'special_auth_endpoint_list': [],
        'server': {
            'enable_basic_auth': False,
            'basic_auth': {
                'iris_twilio_user': 'test-user'
            },
            'debug': False
        },
        'oncall': {
            'relay_app_name': 'test-app',
            'url': 'http://localhost:8080',
            'api_key': 'test-key'
        },
        'iris': {
            'relay_app_name': 'test-app',
            'host': 'http://localhost:16649',
            'api_key': 'test-key',
            'hook': {
                'gmail': 'response/gmail',
                'gmail_one_click': 'response/gmail-oneclick',
                'twilio_calls': 'response/twilio/calls',
                'twilio_messages': 'response/twilio/messages',
                'twilio_status': 'twilio/deliveryupdate',
                'slack': 'response/slack'
            }
        },
        'twilio': {
            'auth_token': 'test-token'
        },
        'saml': {
            'metadata_url_for': {'idp': 'https://fake-idp.test/metadata', 'okta': 'https://dummy-okta.metadata.test'},
            'metadata': {},
            'acs_format': 'http://localhost:16648/saml/sso/%s',
            'https_acs_format': 'https://localhost/saml/sso/%s',
            'entity_id': 'http://localhost/idp'
        },
        'iris-mobile': {
            'activated': True,
            'relay_app_name': 'iris-mobile',
            'host': 'localhost',
            'port': 16649,
            'api_key': 'mobile-key',
            'auth': {
                'access_ttl': 28800,
                'refresh_ttl': 604800,
                'time_window': 90,
                'redirect_url': 'iris://auth',
                'username_attr': 'sAMAccountName',
                'encrypt_key': Fernet.generate_key().decode('utf-8')
            },
            'oncall': {
                'activated': True,
                'url': 'http://localhost:8080',
                'api_key': 'foo'
            }
        },
        'gmail': {
            'project': 'test-project',
            'token': 'test-token',
            'subscription': 'test-sub',
            'topic': 'test-topic',
            'sub': 'test-user@localhost',
            'scope': ['https://mail.google.com/'],
            'creds': './test_creds.json',
            'var_dir': './var',
            'push_endpoint': 'http://localhost/gmail/push',
            'verification_code': 'google12345.html',
            'gmail_one_click_url_key': 'test-key',
        },
        'slack': {
            'verification_token': 'test-slack-token'
        },
        'gmail_one_click_url_key': 'test-key',
        'healthcheck_path': '/tmp/test_health',
        'datadog': {},
        'sender_blacklist': [],
        'db': {
            'conn': {
                'kwargs': {
                    'scheme': 'mysql+pymysql',
                    'user': 'root',
                    'password': '',
                    'host': 'localhost',
                    'database': 'iris',
                    'charset': 'utf8mb4',
                    'echo': False
                },
                'str': '%(scheme)s://%(user)s:%(password)s@%(host)s/%(database)s?charset=%(charset)s'
            },
            'kwargs': {
                'pool_recycle': 3600
            }
        }

    }


@pytest.fixture
def client():
    config = minimal_test_config()
    return testing.TestClient(get_relay_app(config=config))


@patch('iris_relay.app.db.connect')
def test_saml_initiate_and_payload_recovery(mock_db_connect):
    # Step 1: prepare test key and values
    key_bytes = Fernet.generate_key()
    client_key = key_bytes.decode("utf-8")
    device_id = "test-device-xyz"

    # Step 2: mock DB connection
    mock_cursor = MagicMock()
    mock_cursor.fetchone.return_value = [0]
    mock_conn = MagicMock()
    mock_conn.cursor.return_value = mock_cursor
    mock_db_connect.return_value = mock_conn

    # Step 3: mock Falcon req/resp
    mock_req = MagicMock()
    mock_req.context = {
        "body": ujson.dumps({
            "client_key": client_key,
            "device_id": device_id
        }).encode("utf-8")
    }

    mock_resp = MagicMock()

    # Step 4: run the handler
    handler = SAMLInitiate()
    handler.on_post(mock_req, mock_resp)

    # Step 5: verify HTTP 200 and JSON payload
    assert mock_resp.status == "200 OK"
    assert mock_resp.content_type == "application/json"

    payload = ujson.loads(mock_resp.body)
    assert "saml_session_id" in payload
    assert uuid.UUID(payload["saml_session_id"])  # validate UUID format

    # Step 6: verify that the insert query was called with correct values
    args = mock_cursor.execute.call_args[0][1]
    assert args[1] == client_key
    assert args[2] == device_id


def make_encoded_relay_state(session_id="test-session-id", location="app://return"):
    payload = ujson.dumps({
        "saml_session_id": session_id,
        "location": location
    })
    return base64.urlsafe_b64encode(payload.encode("utf-8")).decode("utf-8")


@patch('iris_relay.app.db.connect')
@patch.object(IDPInitiated, 'validate_and_consume_saml_id')
@patch('hashlib.sha256')
def test_idp_initiated_encrypted_flow(mock_sha256, mock_validate, mock_db_connect):
    # Step 1: Create a fixed refresh token
    expected_token = "fixed-refresh-token-abc123"
    mock_hash = MagicMock()
    mock_hash.hexdigest.return_value = expected_token
    mock_sha256.return_value = mock_hash

    # Step 2: Generate a valid Fernet key (as string, like from client)
    client_key_bytes = Fernet.generate_key()
    client_key_str = client_key_bytes.decode("utf-8")  # simulate client-provided key

    saml_session_id = "test-session-id"
    redirect_location = "app://return"
    relay_state = make_encoded_relay_state(saml_session_id, redirect_location)
    req_id = "req-abc-123"
    username = "testuser"
    device_id = "device-xyz"

    # Step 3: Mock DB session + token insert
    mock_cursor = MagicMock()
    mock_cursor.fetchone.return_value = (client_key_str, device_id)
    mock_cursor.lastrowid = 99
    mock_conn = MagicMock()
    mock_conn.cursor.return_value = mock_cursor
    mock_db_connect.return_value = mock_conn

    # Step 4: Mock SAML response
    mock_authn_response = MagicMock()
    mock_authn_response.in_response_to = req_id
    mock_authn_response.get_subject.return_value.text = username
    mock_authn_response.ava = {"username": [username]}

    saml_client = MagicMock()
    saml_client.parse_authn_request_response.return_value = mock_authn_response
    saml_manager = MagicMock()
    saml_manager.saml_client_for.return_value = saml_client

    # Step 5: Set up handler
    encrypt_key_bytes = Fernet.generate_key()
    config = {
        "access_ttl": 300,
        "refresh_ttl": 3600,
        "redirect_url": redirect_location,
        "encrypt_key": encrypt_key_bytes,
        "username_attr": "username"
    }

    handler = IDPInitiated(config, saml_manager, saml_encryption=True)

    # Step 6: Prepare mock Falcon request/response
    form_body = f"SAMLResponse=mocked_response&RelayState={relay_state}"
    mock_req = MagicMock()
    mock_req.context = {"body": form_body.encode("utf-8")}
    mock_resp = MagicMock()

    # Step 7: Call the handler
    handler.on_post(mock_req, mock_resp, idp_name="linkedin")

    # Step 8: Validate redirect and extract encrypted data
    redirect_arg = next(
        call.args[1]
        for call in mock_resp.set_header.call_args_list
        if call.args[0] == 'Location'
    )
    assert redirect_arg.startswith(redirect_location + "?data=")
    encrypted_data = redirect_arg.split("?data=")[1]
    fernet = Fernet(client_key_str.encode("utf-8"))
    decrypted = ujson.loads(fernet.decrypt(encrypted_data.encode("utf-8")).decode("utf-8"))

    # Step 9: Assert payload contents
    assert decrypted["token"] == expected_token
    assert decrypted["keyId"] == 99
    assert decrypted["username"] == username
    assert decrypted["device_id"] == device_id
    assert isinstance(decrypted["created"], int)
    assert isinstance(decrypted["expiry"], float)

    # Final: ensure validate was called
    mock_validate.assert_called_once_with(mock_cursor, req_id)


@patch('iris_relay.app.db.connect')
@patch.object(IDPInitiated, 'validate_and_consume_saml_id')
def test_idp_initiated_legacy_token_flow(mock_validate, mock_db_connect):
    # No session ID in RelayState, simulates legacy client
    legacy_relay_state = "app://legacy-return"
    req_id = "req-abc-123"

    # Mock DB cursor: no session data
    mock_cursor = MagicMock()
    mock_cursor.fetchone.return_value = None  # no saml_login_session
    mock_cursor.lastrowid = 88
    mock_conn = MagicMock()
    mock_conn.cursor.return_value = mock_cursor
    mock_db_connect.return_value = mock_conn

    # Mock SAML response
    mock_authn_response = Mock()
    mock_authn_response.in_response_to = req_id
    mock_authn_response.get_subject.return_value.text = "legacyuser"
    mock_authn_response.ava = {"username": ["legacyuser"]}

    saml_client = Mock()
    saml_client.parse_authn_request_response.return_value = mock_authn_response
    saml_manager = Mock()
    saml_manager.saml_client_for.return_value = saml_client

    config = {
        "access_ttl": 300,
        "refresh_ttl": 3600,
        "redirect_url": legacy_relay_state,
        "encrypt_key": Fernet.generate_key().decode("utf-8"),
        "username_attr": "username"
    }

    handler = IDPInitiated(config, saml_manager, saml_encryption=False)  # encryption OFF

    form_body = f"SAMLResponse=mocked_response&RelayState={legacy_relay_state}"
    mock_req = Mock()
    mock_req.context = {"body": form_body.encode("utf-8")}
    mock_resp = Mock()

    handler.on_post(mock_req, mock_resp, idp_name="linkedin")

    mock_validate.assert_called_once_with(mock_cursor, req_id)

    redirect_arg = next(call.args[1] for call in mock_resp.set_header.call_args_list if call.args[0] == 'Location')
    assert "#token=" in redirect_arg
    assert redirect_arg.startswith(legacy_relay_state + "#token=")
    assert mock_resp.status.startswith("302")


@patch('iris_relay.app.db.connect')
@patch.object(IDPInitiated, 'validate_and_consume_saml_id')
@patch('iris_relay.app.SAML.saml_client_for')
def test_idp_initiated_with_legacy_relaystate_returns_legacy_token(
    mock_saml_client_for,
    mock_validate,
    mock_db_connect,
    client
):
    # Mock SAML authn response
    mock_authn_response = MagicMock()
    mock_authn_response.get_subject.return_value.text = "testuser"
    mock_authn_response.ava = {'sAMAccountName': ['testuser']}
    mock_authn_response.in_response_to = "request-id"
    mock_saml_client_for.return_value.parse_authn_request_response.return_value = mock_authn_response

    # Mock DB interaction for refresh_token insert
    mock_cursor = MagicMock()
    mock_cursor.lastrowid = 123
    mock_connection = MagicMock()
    mock_connection.cursor.return_value = mock_cursor
    mock_db_connect.return_value = mock_connection

    # Simulate legacy RelayState (non-base64)
    saml_response = base64.b64encode(b"<xml>SAML</xml>").decode()
    resp = client.simulate_post('/saml/sso/okta', headers={
        'Content-Type': 'application/x-www-form-urlencoded'
    }, body=f"SAMLResponse={saml_response}&RelayState=this-is-not-base64")

    # Assert legacy redirect behavior
    assert resp.status_code == 302
    assert 'token=' in resp.headers['Location']
    assert '#token=' in resp.headers['Location']


@patch('iris_relay.app.db.connect')
@patch.object(IDPInitiated, 'validate_and_consume_saml_id')
@patch('hashlib.sha256')
def test_idp_initiated_legacy_relaystate_rejected_when_encryption_enabled(mock_sha256, mock_validate, mock_db_connect):
    # Generate a fixed token to make assertion cleaner
    mock_hash = MagicMock()
    mock_hash.hexdigest.return_value = "irrelevant"
    mock_sha256.return_value = mock_hash

    # Prepare mocks: DB connection won't matter, as session_id won't be used
    mock_cursor = MagicMock()
    mock_conn = MagicMock()
    mock_conn.cursor.return_value = mock_cursor
    mock_db_connect.return_value = mock_conn

    # Simulate valid SAML response
    username = "testuser"
    req_id = "req-legacy-123"
    mock_authn_response = MagicMock()
    mock_authn_response.in_response_to = req_id
    mock_authn_response.get_subject.return_value.text = username
    mock_authn_response.ava = {"username": [username]}

    saml_client = MagicMock()
    saml_client.parse_authn_request_response.return_value = mock_authn_response
    saml_manager = MagicMock()
    saml_manager.saml_client_for.return_value = saml_client

    # Config with saml_encryption enabled
    config = {
        "access_ttl": 300,
        "refresh_ttl": 3600,
        "redirect_url": "app://fallback",
        "encrypt_key": Fernet.generate_key(),
        "username_attr": "username"
    }

    handler = IDPInitiated(config, saml_manager, saml_encryption=True)

    # RelayState is a plain string (legacy), not base64
    legacy_relay_state = "app://fallback"
    form_body = f"SAMLResponse=mocked_response&RelayState={legacy_relay_state}"
    mock_req = MagicMock()
    mock_req.context = {"body": form_body.encode("utf-8")}
    mock_resp = MagicMock()

    # Expect this to raise due to saml_encryption + no session
    with pytest.raises(falcon.HTTPBadRequest) as excinfo:
        handler.on_post(mock_req, mock_resp, idp_name="linkedin")
        assert isinstance(excinfo.value, falcon.HTTPBadRequest)


def test_saml_initiate_with_invalid_key_returns_400(client):
    bad_key = "notbase64"  # not a valid Fernet key
    resp = client.simulate_post('/saml/initiate', json={
        "client_key": bad_key,
        "device_id": "device-abc"
    })
    assert resp.status_code == 400
    assert b'Invalid client_key format' in resp.content


def test_saml_initiate_missing_fields_returns_400(client):
    # Missing device_id
    resp = client.simulate_post('/saml/initiate', json={
        "client_key": Fernet.generate_key().decode()
    })
    assert resp.status_code == 400
    assert b'Missing client_key or device_id' in resp.content


def test_saml_initiate_db_session_limit_returns_429(client, mocker):
    mock_cursor = mocker.MagicMock()
    mock_cursor.fetchone.return_value = (MAX_LOGIN_SESSIONS,)
    mock_conn = mocker.MagicMock()
    mock_conn.cursor.return_value = mock_cursor
    mocker.patch('iris_relay.db.connect', return_value=mock_conn)

    resp = client.simulate_post('/saml/initiate', json={
        "client_key": Fernet.generate_key().decode(),
        "device_id": "device-xyz"
    })
    assert resp.status_code == 429
    assert b'Too many active login sessions' in resp.content
