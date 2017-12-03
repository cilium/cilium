******************
Command Cheatsheet
******************

Below is a short list of examples of the various commands Cilium has to offer.
If a command you use is missing please don’t hesitate to add it to one of the
groups or create a new one.

Basics
======

::

        # Check the status of the agent

        cilium status

::

        # Get the current agent configuration

        cilium config

Policy management
=================

::

	# Importing a policy

	cilium policy import <my-policy.json>

::

	# Get list of all imported policy rules

	cilium policy get

::

	# Remove all policy

	cilium policy delete --all

Monitoring
==========

::

	# Monitor cilium datapath notifications

	cilium monitor 

::

	# Verbose output (including debug if enabled)

	cilium monitor -v

::

        # Filter for only the events to endpoint

        cilium monitor --related-to=<id>

::

	# Show notifications only for dropped packet events

	cilium monitor --type drop

::

	# Don't dissect packet payload, display payload in hex format

	cilium monitor -v --hex

Endpoints
=========

::

	# Get list of all local endpoints

	cilium endpoint list

::

        # Get detailed view of endpoint properties and state

        cilium endpoint get <id>

::

        # Show recent endpoint specific log entries

        cilium endpoint log <id>

::

	# Enable debugging output on the cilium monitor for this endpoint

	cilium endpoint config <id> Debug=true

Tracing
=======

::

	# Check policy enforcement between two labels on port 80

	cilium policy trace -s <app.from> -d <app.to> --dport 80

::

        # Check policy enforcement between two identities

        cilium policy trace --src-identity <from-id> --dst-identity <to-id>

::

        # Check policy enforcement between two pods

        cilium policy trace --src-k8s-pod <namespace>:<pod.from> --dst-k8s-pod <namespace>:<pod.to>

Loadbalancing
=============


::

        # Get list of loadbalancer services

        cilium service list

BPF
===

::

        # List node tunneling mapping information

        cilium bpf tunnel list

::

        # Checking logs for verifier issue

        journalctl -u cilium | grep -B20 -F10 Verifier
