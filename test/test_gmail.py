from iris_relay.gmail import Gmail


def test_filter_pointless_messages():
    bad_message = {
      'payload': {'headers': [
          {
            'name': 'X-Autoreply',
            'value': 'yes'
          }
      ]}
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
      'payload': {'headers': [
          {
            'name': 'From',
            'value': 'Foo Bar <foo@bar.com>'
          }
      ]}
    }

    missing_info_message = {}

    assert not Gmail.filter_pointless_messages(bad_message)
    assert not Gmail.filter_pointless_messages(bad_message2)

    assert Gmail.filter_pointless_messages(good_message)
    assert Gmail.filter_pointless_messages(missing_info_message)
