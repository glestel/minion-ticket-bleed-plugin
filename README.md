Minion Ticketbleed Plugin
===================

This is a plugin for Minion that run a check for Ticketbleed (CVE-2016-9244) vulnerability on F5 TLS layer.
The test can either runs as a go script or an linux binary. The script is improved from [https://filippo.io/Ticketbleed/](this site)

Installation
------------

Clone the project with ``git clone https://github.com/glestel/minion-ticket-bleed-plugin.git``

Then in the project repertory, you can install the plugin by running the following command in the minion-schedule-plugin repository (with the virtual environment activated if needed): 
by the command

```python setup.py develop```

Compiling Go binary
---------------
Once you have installed your go environment, in the directory of the plugin, run
`go build ticketbuild.go` and specify the path to the created binary in the plan configuration.

Example of plan
---------------

```
[
  {
    "configuration": {
      "report_dir": "/tmp/artifacts/",
      "ticket_path": "/home/user/minion/minion-ticket-bleed-plugin/ticketbleed"
    },
    "description": "Check vulnerabity of TicketBleed for F5",
    "plugin_name": "minion.plugins.ticket_bleed_plugin.TicketBleedPlugin"
  }
]
```
Available configuration option
------------------------------
Most of the options are not mandatory and have default values.
* ```report_dir``` : directory where the reports will be saved. By default, the path used is `/tmp/artifacts`
* ```ticket_path ``` : path of the binary that will run the scan




