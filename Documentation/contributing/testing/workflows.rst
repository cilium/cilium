.. only:: not (epub or latex or html)

    WARNING: You are looking at unreleased Cilium documentation.
    Please use the official rendered version released here:
    https://docs.cilium.io

.. _workflows:

GitHub Workflows Testing Framework
==================================

Running GitHub Workflows Locally
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

Running GitHub workflows locally is currently possible with the help of `nektos/act <https://github.com/nektos/act>`_.

Requirements:
 - ``act`` - with commit ``bf4aad6ad296822cb0352e21ce3867284eaf1eff``, build locally by cloning the repository and running ``make build && alias act=$PWD/dist/local/act``
 - ``docker``

Currently, only the following workflows were tested to work with ``act``:

 - .github/workflows/conformance-gke.yaml - :ref:`conformance_gke`

.. _conformance_gke:

Running Conformance GKE
^^^^^^^^^^^^^^^^^^^^^^^

Workflow Requirements:
 - :ref:`gh_token`
 - :ref:`gcp_project_id`
 - :ref:`gcp_sa_key`


Once you have ``GITHUB_TOKEN`` exported and ``secrets-file.txt`` created, run
the following command. As you can see, ``git rev-parse HEAD`` will be used as
the default commit but you can choose any commit that has a docker image
available:

.. code-block:: shell-session

    act -s GITHUB_TOKEN=${GITHUB_TOKEN} \
        --secret-file=secrets-file.txt \
        --env ACT_SHA="$(git rev-parse HEAD)" \
        -e .github/workflows/gke.json \
        issue_comment \
        -W .github/workflows/conformance-gke.yaml

**Tips**:

When debugging a GKE flake it might be worth disabling the deletion and
consequent creation of GKE clusters. This can easily be achieved by adding
``if: ${{ !env.ACT }}`` in the "Create GKE cluster" step:

.. code-block:: diff

           - name: Create GKE cluster
    +        if: ${{ !env.ACT }}
             run: |
               gcloud container clusters create ${{ env.clusterName }} \

and for the cluster cleanup:

.. code-block:: diff

          - name: Clean up GKE
    -       if: ${{ always() }}
    +       if: ${{ !env.ACT && always() }}
            run: |

Workflow Requirements Steps
~~~~~~~~~~~~~~~~~~~~~~~~~~~

.. _gh_token:

GitHub Token with ``public_repo`` access
^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^

`Click here to generate one <https://github.com/settings/tokens/new?description=act%20read%20repo&scopes=public_repo>`_

.. _gcp_project_id:

GCP Project ID
^^^^^^^^^^^^^^

The ``GCP_PROJECT_ID`` secret should point to your GCP Project ID, store this
value in a secrets file:

.. code-block:: shell-session

    SECRET="GCP_PROJECT_ID='$(gcloud config list --format 'value(core.project)' 2>/dev/null)'"; echo $SECRET >> secrets-file.txt; unset SECRET

.. _gcp_sa_key:

GCP SA Key
^^^^^^^^^^

The ``GCP_SA_KEY`` secret can be retrieved by following the steps:

1. Go to `Google Cloud Console > IAM & Admin > Service Accounts <https://console.cloud.google.com/iam-admin/serviceaccounts>`_.

2. If you don't have one already, simply create a new service account and export its key as a JSON file.

   1. Click on the Service Account, go to the "KEYS" tab.
   2. Once in the "KEYS" tab, click on "ADD KEY" > "Create new key"
   3. Store the JSON (``serviceaccount.json``) file somewhere safe.

3. Add the right permissions to this service account:

   1. Go to `Google Cloud Console > IAM & Admin > IAM <https://console.cloud.google.com/iam-admin/iam>`_.
   2. Edit the permissions for that service account and add the "Kubernetes Engine Admin" role to it.

4. Store the ``serviceaccount.json`` in a secrets file:

.. code-block:: shell-session

    SECRET="GCP_PR_SA_KEY='$(cat serviceaccount.json)'"; echo $SECRET >> secrets-file.txt; unset SECRET
