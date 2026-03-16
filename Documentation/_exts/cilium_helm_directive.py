"""
Sphinx directive for generating Cilium helm install/upgrade commands with
OCI Registry tabs for stable versions and simple commands for development.

Usage in RST files:

    .. cilium-helm-install::
       :namespace: kube-system
       :set: image.pullPolicy=IfNotPresent
             ipam.mode=kubernetes

This will generate:
- For stable: tabs showing both Helm Repository and OCI Registry options
- For not stable: a simple helm install command
"""

from docutils import nodes
from docutils.parsers.rst import directives
from docutils.statemachine import StringList
from sphinx.util.docutils import SphinxDirective
from textwrap import dedent


RST_TEMPLATE = """\
.. only:: stable

   .. tabs::

      .. group-tab:: Helm Repository

         .. parsed-literal::

{helm_repo_cmd}

      .. group-tab:: OCI Registry

         .. parsed-literal::

{oci_cmd}

.. only:: not stable

   .. parsed-literal::

{not_stable_cmd}
"""


class CiliumHelmInstallDirective(SphinxDirective):
    """Directive to generate helm install commands with OCI Registry tabs."""

    has_content = False
    required_arguments = 0
    optional_arguments = 0
    final_argument_whitespace = False

    option_spec = {
        'namespace': directives.unchanged,
        'set': directives.unchanged,
        'command': directives.unchanged,
        'name': directives.unchanged,
        'extra-args': directives.unchanged,
        'post-helm-commands': directives.unchanged,
        'post-commands': directives.unchanged,
    }

    def _parse_set_options(self):
        """Parse --set options from newlines/spaces."""
        if 'set' not in self.options:
            return []
        opts = []
        for line in self.options['set'].split('\n'):
            opts.extend(item for item in line.strip().split() if item)
        return opts

    def _build_opts_list(self, namespace, extra_args, set_options):
        """Build the list of helm command options."""
        opts = []
        if namespace:
            opts.append(f'--namespace {namespace}')
        if extra_args:
            opts.append(extra_args)
        opts.extend(f'--set {opt}' for opt in set_options)
        return opts

    def _format_command(self, base_cmd, opts, indent, post_helm_commands='', post_commands=''):
        """Format a helm command with proper line continuation."""
        # Normalize indent
        if isinstance(indent, int):
            indent = ' ' * indent
        cont_indent = indent + '  '

        # Parse post_helm_commands (these get line continuation like helm args)
        post_helm_lines = []
        if post_helm_commands:
            for line in post_helm_commands.split('\n'):
                line = line.strip()
                if line:
                    post_helm_lines.append(line)

        # Parse post_commands (these don't get line continuation)
        post_cmd_lines = []
        if post_commands:
            for line in post_commands.split('\n'):
                line = line.strip()
                if line:
                    post_cmd_lines.append(line)

        # Build the helm command with continuations
        continued_lines = [base_cmd]
        continued_lines.extend(f'{cont_indent}{opt}' for opt in opts)
        continued_lines.extend(f'{cont_indent}{line}' for line in post_helm_lines)

        formatted_lines = []
        for i, line in enumerate(continued_lines):
            # First line needs the base indent
            if i == 0:
                full = f'{indent}{line}'
            else:
                full = line
            # Add '\' for all but the last continued line
            if i < len(continued_lines) - 1:
                full += ' \\'
            formatted_lines.append(full)

        # Append post commands without continuation
        for line in post_cmd_lines:
            formatted_lines.append(f'{indent}{line}')

        # Ensure trailing newline for RST literal blocks
        return '\n'.join(formatted_lines) + '\n'

    def run(self):
        # Options
        namespace = self.options.get('namespace')
        extra_args = self.options.get('extra-args', '')
        set_options = self._parse_set_options()
        opts = self._build_opts_list(namespace, extra_args, set_options)

        command = self.options.get('command', 'upgrade --install')
        name = self.options.get('name', 'cilium')

        post_helm_commands = self.options.get('post-helm-commands', '')
        post_commands = self.options.get('post-commands', '')

        # Base charts for different sources
        helm_repo_chart = 'cilium/cilium'
        oci_chart = 'oci://ghcr.io/cilium/charts/cilium'
        dev_chart = './cilium'

        # Build base commands
        helm_repo_base = f'helm {command} {name} {helm_repo_chart}'
        oci_base = f'helm {command} {name} {oci_chart}'
        not_stable_base = f'helm {command} {name} {dev_chart}'

        # Indents for RST literal blocks inside tabs/only blocks
        stable_tab_indent = ' ' * 12
        not_stable_indent = ' ' * 6

        helm_repo_cmd = self._format_command(
            helm_repo_base, opts, stable_tab_indent,
            post_helm_commands=post_helm_commands, post_commands=post_commands
        )
        oci_cmd = self._format_command(
            oci_base, opts, stable_tab_indent,
            post_helm_commands=post_helm_commands, post_commands=post_commands
        )
        not_stable_cmd = self._format_command(
            not_stable_base, opts, not_stable_indent,
            post_helm_commands=post_helm_commands, post_commands=post_commands
        )

        rst = dedent(RST_TEMPLATE).format(
            helm_repo_cmd=helm_repo_cmd,
            oci_cmd=oci_cmd,
            not_stable_cmd=not_stable_cmd,
        )

        lines = StringList(rst.splitlines())
        self.state_machine.insert_input(lines, source=self.state.document.current_source)
        return []


def setup(app):
    app.add_directive('cilium-helm-install', CiliumHelmInstallDirective)
    return {'version': '1.0', 'parallel_read_safe': True}