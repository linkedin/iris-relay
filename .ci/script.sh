#!/bin/bash
set -e

make serve &
make check
