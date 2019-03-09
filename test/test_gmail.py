from iris_relay.gmail import is_pointless_messages, process_message
from base64 import urlsafe_b64encode


def test_is_pointless_messages():
    bad_message = {
        'payload': {
            'headers': [{
                'name': 'X-Autoreply',
                'value': 'yes'
            }]
        }
    }

    bad_message2 = {
        'payload': {'headers': [
            {
                'name': 'Auto-Submitted',
                'value': 'auto-replied'
            },
            {
                'name': 'Precedence',
                'value': 'bulk'
            }
        ]}
    }

    good_message = {
        'payload': {'headers': [{
            'name': 'From',
            'value': 'Foo Bar <foo@bar.com>'
        }]}
    }

    missing_info_message = {}

    assert is_pointless_messages(bad_message)
    assert is_pointless_messages(bad_message2)

    assert not is_pointless_messages(good_message)
    assert not is_pointless_messages(missing_info_message)


def test_process_message_text_plain():
    fake_headers = [{'name': 'Content-Type', 'value': 'text/plain; charset="us-ascii"'}]
    fake_content = 'hello'
    fake_content = fake_content.encode('utf8')
    fake_message = {'payload': {
        'headers': fake_headers,
        'parts': [{'mimeType': 'text/plain', 'body': {'data': urlsafe_b64encode(fake_content)}}]
    }}
    is_message_processed = False
    for headers, content in process_message(fake_message):
        is_message_processed = True
        assert headers == fake_headers
        assert content == fake_content
    assert is_message_processed


def test_process_message_multipart():
    fake_headers = [{
        'name': 'Content-Type',
        'value': 'multipart/alternative; boundary="===============3481026495533768394=="'
    }]
    fake_content = 'hello'
    fake_content = fake_content.encode('utf8')
    fake_message = {
        'payload': {
            'headers': fake_headers,
            'mimeType': 'multipart/related',
            'parts': [{
                'headers': fake_headers,
                'mimeType': 'multipart/alternative',
                'parts': [
                    {
                        'mimeType': 'text/plain',
                        'body': {'data': urlsafe_b64encode(fake_content)}
                    }
                ]
            }]
        }
    }
    is_message_processed = False
    for headers, content in process_message(fake_message):
        is_message_processed = True
        assert headers == fake_headers
        assert content == fake_content
    assert is_message_processed
