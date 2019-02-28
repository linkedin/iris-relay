# Copyright (c) LinkedIn Corporation. All rights reserved. Licensed under the BSD-2 Clause license.
# See LICENSE in the project root for license information.


from iris_relay.app import read_config_from_argv
from iris_relay.gmail import Gmail

config = read_config_from_argv()
gmclient = Gmail(config.get('gmail'), config.get('proxy'))

print('Fetching unread messages...')
for msg_id_gmail, headers, body in gmclient.list_unread_message():
    print({'body': body, 'headers': headers})
