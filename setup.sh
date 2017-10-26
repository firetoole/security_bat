#!/bin/bash

virtualenv -q -p /usr/bin/python2.7 . $1
$1/usr/local/bin/pip install -r requirements.txt