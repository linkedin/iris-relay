# Copyright (c) LinkedIn Corporation. All rights reserved. Licensed under the BSD-2 Clause license.
# See LICENSE in the project root for license information.

import os
import yaml
from iris_relay.app import get_relay_app

with open(os.environ['CONFIG']) as config_file:
    config = yaml.safe_load(config_file)

application = get_relay_app(config)
