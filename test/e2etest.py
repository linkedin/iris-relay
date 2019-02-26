import requests

host = 'http://0.0.0.0:16648'
base_url = host + '/api/v0/'


def test_health():
    """
    Should respond to health check
    """
    re = requests.get(host + '/healthcheck')
    assert re.status_code == 200
    assert re.content == 'GOOD'
