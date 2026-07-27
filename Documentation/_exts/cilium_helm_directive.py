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
        # Parse post_helm_commands (these get line continuation like helm args)
        post_helm_lines = []
        if post_helm_commands:
            for line in post_helm_commands.split('\n'):
                if line:
                    post_helm_lines.append(line)

        # Parse post_commands (these don't get line continuation)
        post_cmd_lines = []
        if post_commands:
            for line in post_commands.split('\n'):
                if line:
                    post_cmd_lines.append(line)

        if not opts and not post_helm_lines and not post_cmd_lines:
            return f'{indent}{base_cmd}'

        has_post_helm = len(post_helm_lines) > 0
        has_post_cmd = len(post_cmd_lines) > 0

        lines = [f'{indent}{base_cmd} \\\\']

        # Add regular options with line continuation
        for i, opt in enumerate(opts):
            is_last = (i == len(opts) - 1) and not has_post_helm
            suffix = '' if is_last else ' \\\\'
            lines.append(f'{indent}   {opt}{suffix}')

        # Add post_helm_commands - no line continuation, just aligned with other args
        for line in post_helm_lines:
            lines.append(f'{indent}   {line}')

        # Add post_commands without line continuation
        for line in post_cmd_lines:
            lines.append(f'{indent}{line}')

        return '\n'.join(lines)

    def run(self):
        namespace = self.options.get('namespace', 'kube-system')
        command = self.options.get('command', 'install')
        name = self.options.get('name', 'cilium')
        extra_args = self.options.get('extra-args', '')
        post_helm_commands = self.options.get('post-helm-commands', '')
        post_commands = self.options.get('post-commands', '')

        set_options = self._parse_set_options()
        opts_list = self._build_opts_list(namespace, extra_args, set_options)

        # For template command, format is "helm template |CHART_RELEASE|" (no name)
        # For install/upgrade, format is "helm install name |CHART_RELEASE|"
        if command == 'template':
            helm_repo_base = f'helm {command} |CHART_RELEASE|'
            oci_base = f'helm {command} oci://quay.io/cilium/charts/cilium |CHART_VERSION|'
        else:
            helm_repo_base = f'helm {command} {name} |CHART_RELEASE|'
            oci_base = f'helm {command} {name} oci://quay.io/cilium/charts/cilium |CHART_VERSION|'

        # Build formatted commands for each section
        helm_repo_cmd = self._format_command(
            helm_repo_base,
            opts_list, '            ', post_helm_commands, post_commands
        )
        oci_cmd = self._format_command(
            oci_base,
            opts_list, '            ', post_helm_commands, post_commands
        )
        not_stable_cmd = self._format_command(
            helm_repo_base,
            opts_list, '      ', post_helm_commands, post_commands
        )

        # Generate RST from template
        rst_content = RST_TEMPLATE.format(
            helm_repo_cmd=helm_repo_cmd,
            oci_cmd=oci_cmd,
            not_stable_cmd=not_stable_cmd,
        )

        # Parse and return nodes
        string_list = StringList(
            rst_content.splitlines(),
            source=self.state_machine.document['source']
        )
        node = nodes.container()
        node.document = self.state.document
        self.state.nested_parse(string_list, 0, node)
        return node.children


class CiliumHelmUpgradeDirective(CiliumHelmInstallDirective):
    """Directive to generate helm upgrade commands with OCI Registry tabs."""

    def run(self):
        if 'command' not in self.options:
            self.options['command'] = 'upgrade'
        return super().run()


class CiliumHelmTemplateDirective(CiliumHelmInstallDirective):
    """Directive to generate helm template commands with OCI Registry tabs."""

    def run(self):
        if 'command' not in self.options:
            self.options['command'] = 'template'
        return super().run()


def setup(app):
    app.add_directive('cilium-helm-install', CiliumHelmInstallDirective)
    app.add_directive('cilium-helm-upgrade', CiliumHelmUpgradeDirective)
    app.add_directive('cilium-helm-template', CiliumHelmTemplateDirective)

    return {
        'version': '1.0',
        'parallel_read_safe': True,
        'parallel_write_safe': True,
    }
