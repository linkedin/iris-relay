import requests
import pytest

host = 'http://localhost:16648'
base_url = host + '/api/v0/'


@pytest.mark.skip(reason='re-enable this when we have additional logic here to get a working msg_id and email address')
def test_gmail_one_click_success():
    re = requests.get(base_url + 'gmail-oneclick/relay', params={
        'token': 'kBfq3A0qc4ea4OLCQeZXJG1XEKNYih0Q6jCPwZ2D2SiAdb36jh4Bjci_rDQwpVgRaegPOcJut3xz1dgmF3l7KQ==',
        'msg_id': 351192,
        'email_address': 'email@email.com',
        'cmd': 'claim',
    })
    assert re.status_code == 204


def test_gmail_one_click_bad_token():
    re = requests.get(base_url + 'gmail-oneclick/relay', params={
        'token': 'faketoken',
        'msg_id': 351192,
        'email_address': 'foo@foo.com',
        'cmd': 'claim',
    })
    assert re.status_code == 403


# test twilio related APIs

def test_twilio_phone_say_api():
    """
    Used by iris-api to send a phonecall that does not require user response
    """
    signature = '5WpPirTeX68acyr4NFVVtMevJdU='
    re = requests.get(base_url + 'twilio/calls/say?content=hello',
                      headers={'X-Twilio-Signature': signature})
    assert re.status_code == 200
    assert re.content == (
        '<?xml version="1.0" encoding="UTF-8"?>'
        '<Response><Say language="en-US" voice="alice">hello</Say>'
        '</Response>')
    assert re.headers['content-type'] == 'application/xml'

    # Should have the same behavior on post
    re = requests.post(base_url + 'twilio/calls/say?content=hello',
                       headers={'X-Twilio-Signature': signature})
    assert re.status_code == 200
    assert re.content == (
        '<?xml version="1.0" encoding="UTF-8"?>'
        '<Response><Say language="en-US" voice="alice">hello</Say>'
        '</Response>')
    assert re.headers['content-type'] == 'application/xml'


def test_twilio_phone_gather_api():
    """
    Used by iris-api to send a phonecall that requires user response
    This is step 1
    """
    re = requests.post(
        base_url + 'twilio/calls/gather',
        params={
            'content': 'foo',
            'instruction': 'bar',
            'message_id': 1001,
        },
        headers={'X-Twilio-Signature': 'EgL9vRByfCmVTsAcYRgq3e+nBHw='})
    assert re.status_code == 200
    assert re.content == (
        '<?xml version="1.0" encoding="UTF-8"?><Response>'
        '<Pause length="2" />'
        '<Say language="en-US" voice="alice">Press pound for menu.</Say>'
        '<Gather finishOnKey="#" timeout="0">'
        '<Say language="en-US" voice="alice">foo</Say>'
        '</Gather>'
        '<Gather'
        # use this if we have lb_routing_path config set:
        # ' action="%s/iris-relay/api/v0/twilio/calls/relay?message_id=1001"'
        ' action="%s/api/v0/twilio/calls/relay?message_id=1001"'
        ' numDigits="1"><Say language="en-US" voice="alice">bar</Say>'
        '</Gather></Response>'
    ) % host
    assert re.headers['content-type'] == 'application/xml'


def test_twilio_phone_gather_api_batch_message_id():
    fake_batch_id = '06d7bbacb29f41ab9a74074364b03516'
    params = {
        'content': 'bar',
        'source': 'Autoalerts',
        'instruction': 'Press 2 to claim.',
        'message_id': fake_batch_id,
        'loop': 3,
    }
    re = requests.post(
        base_url + 'twilio/calls/gather', params=params,
        headers={'X-Twilio-Signature': 'y4SPekGJdZ1oH1k/UHFdf29epbo='})
    assert re.status_code == 200
    assert re.content == (
        '<?xml version="1.0" encoding="UTF-8"?><Response>'
        '<Pause length="2" />'
        '<Say language="en-US" voice="alice">Press pound for menu.</Say>'
        '<Gather finishOnKey="#" timeout="0">'
        '<Say language="en-US" voice="alice">bar</Say>'
        '</Gather>'
        '<Gather'
        # use this if we have lb_routing_path config set:
        # ' action="%s/iris-relay/api/v0/twilio/calls/relay?message_id=%s"'
        ' action="%s/api/v0/twilio/calls/relay?message_id=%s"'
        ' numDigits="1">'
        '<Say language="en-US" loop="3" voice="alice">Press 2 to claim.</Say>'
        '</Gather></Response>'
    ) % (host, fake_batch_id)
    assert re.headers['content-type'] == 'application/xml'

    params['message_id'] = ['arbitrary text']
    re = requests.post(
        base_url + 'twilio/calls/gather', params=params,
        headers={'X-Twilio-Signature': 'UNHsmlgrXLq1GSsmDCeuJcYC2S0='})
    assert re.status_code == 400


def test_twilio_phone_relay_api():
    """
    Used by iris-api to send a phonecall that requires user response
    This is step 2
    """
    fake_sid = 'AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA'
    re = requests.post(
        base_url + 'twilio/calls/relay',
        params={'message_id': 1001},
        headers={'X-Twilio-Signature': 'ykIcAuORO+RmJtm3qFi5ntlhZbE='},
        data='AccountSid=%s&ToZip=15108&FromState=CA&Digits=1' % fake_sid)
    assert re.status_code == 200
    assert re.headers['content-type'] == 'application/xml'

    # Test unauthorized for missing sig
    re = requests.post(
        base_url + 'twilio/calls/relay',
        params={'message_id': 1001},
        data='AccountSid=%s&ToZip=15108&FromState=CA&Digits=1' % fake_sid)
    assert re.status_code == 401

    # Test Unauthorized for bad sig
    re = requests.post(
        base_url + 'twilio/calls/relay',
        params={'message_id': 1001},
        headers={'X-Twilio-Signature': 'foobar='},
        data='AccountSid=%s&ToZip=15108&FromState=CA&Digits=1' % fake_sid)
    assert re.status_code == 401


def test_twilio_message_relay_api():
    """
    Twilio hits this endpoint whenever user sends a SMS to our twilio number
    """
    fake_sid = 'AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA'
    re = requests.post(
        base_url + 'twilio/messages/relay',
        params={'message_id': 1001},
        headers={'X-Twilio-Signature': 'xjJ+JooosEwujd1Aqe3HRyA17vI='},
        data="AccountSid=%s&ToZip=15108&FromState=CA" % fake_sid)
    assert re.status_code == 200
    assert re.headers['content-type'] == 'application/xml'


def test_health():
    """
    Should respond to health check
    """
    re = requests.get(host + '/healthcheck')
    assert re.status_code == 200
    assert re.content == 'GOOD'


def test_gmail_verification():
    """
    Should respond with Gmail verification code
    """
    # The ['gmail']['verification_code'] config value becomes this weird route
    # path
    re = requests.get(host + '/googleabcdefg.html')
    assert re.status_code == 200
    assert re.content == 'google-site-verification: googleabcdefg.html'
