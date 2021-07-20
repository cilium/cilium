#!/usr/bin/env bash

ansible-playbook -u vagrant --skip-tags=common:delete site.yml
ansible-playbook -u vagrant --tags=common:delete site.yml
