#!/usr/bin/env python

# Copyright (c) LinkedIn Corporation. All rights reserved. Licensed under the BSD-2 Clause license.
# See LICENSE in the project root for license information.

import sys
import yaml
import multiprocessing
import gunicorn.app.base


class StandaloneApplication(gunicorn.app.base.BaseApplication):

    def __init__(self, options=None, skip_build_assets=False):
        self.options = options or {}
        self.skip_build_assets = skip_build_assets
        super(StandaloneApplication, self).__init__()

    def load_config(self):
        config = {key: value for key, value in self.options.items()
                  if key in self.cfg.settings and value is not None}
        for key, value in config.items():
            self.cfg.set(key.lower(), value)

    def load(self):
        from iris_relay.app import get_relay_app
        with open(sys.argv[1]) as config_file:
            config = yaml.safe_load(config_file)
            return get_relay_app(config)


def main():
    if len(sys.argv) <= 1:
        sys.exit('USAGE: %s CONFIG_FILE [--skip-build-assets]' % sys.argv[0])
    elif len(sys.argv) >= 3:
        skip_build_assets = (sys.argv[2] == '--skip-build-assets')
    else:
        skip_build_assets = False

    with open(sys.argv[1]) as config_file:
        config = yaml.safe_load(config_file)
    server = config['server']

    options = {
        'preload_app': False,
        'reload': True,
        'bind': '%s:%s' % (server['host'], server['port']),
        'worker_class': 'gevent',
        'accesslog': '-',
        'workers': multiprocessing.cpu_count()
    }

    gunicorn_server = StandaloneApplication(options, skip_build_assets)
    gunicorn_server.run()


if __name__ == '__main__':
    main()
