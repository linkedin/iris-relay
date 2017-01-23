import requests
import pytest

host = 'http://localhost:16648'
base_url = host+'/api/v0/'


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
