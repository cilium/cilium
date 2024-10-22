# Configuring Neovim for Cilium Debugging

Cilium provides an instrumented Kind deployment which binds DAP debugging ports
to the localhost.

The `vscode` editor will discover a file named `.vscode/launch.json` in a project's
root directory and configure `vscode`'s debugger panel with the necessary information
to connect to these ports for debugging without any configuration needed by the
user.

We've devised a way for this to seamlessly work with Neovim as well.

The following plugins are required:

[nvim-dap](https://github.com/mfussenegger/nvim-dap) - the DAP client

[nvim-dap-ui](https://github.com/rcarriga/nvim-dap-ui) - the UI elements for interfacing
with nvim-dap

[nvim-dap-projects](https://github.com/ldelossa/nvim-dap-projects) - a configuration
discovery mechanism for nvim-dap configuration.

You can use your favorite plugin manager but here is an example configuration
using Plug

```
call plug#begin('~/.config/nvim/plugins')
    Plug 'mfussenegger/nvim-dap'
    Plug 'rcarriga/nvim-dap-ui'
    Plug 'ldelossa/nvim-dap-projects'
call plug#end()
lua require('nvim-dap-projects').search_project_config()
```

Once all three plugins are installed you should make a call to
`lua require('nvim-dap-projects').search_project_config()`.

This function will find the `nvim-dap.lua` file in the Cilium repository and
load it.

You can now use nvim-dap as normal.

This README will not be a nvim-dap tutorial but for a quick test you can create
a breakpoint in your Cilium source code with the command `DapToggleBreakpoint`
and then issue the command `DapContinue`. A UI should pop up asking you to select
one of several Kind nodes to connect to for debugging.
