#!/usr/bin/env python3

import cmd
import configparser
import sys
import threading

try:
    import colorama
except ImportError:
    exit('Please install colorama for colorful console output: pip install colorama')

try:
    import tabulate
except ImportError:
    exit('Tabulate module is needed for interactive console: "pip install tabulate"')


import core.potloader as potloader
import core.utils as utils
import core.spf as spf


class DDoSPot(cmd.Cmd):
    # one of the reasons for creating an object is that ExtensionsAt object contains a descriptor
    # this descriptor is executed when accessing the attribute, and it will be executed when accessing
    # plugins as a member variable
    plugins = spf.ExtensionsAt(potloader.PotLoader)
    pots = []
    pot_names = []

    def __init__(self, version):
        cmd.Cmd.__init__(self)
        # DDoSPot "constructor" will always be called (both in interactive and non-interactive mode)
        # it is thus safe to init colorama here
        colorama.init(autoreset=True)
        self._read_config()
        self.prompt = colorama.Fore.GREEN + 'ddp > '
        self.doc_header = 'Available commands (use help <command> for detailed help):'
        self.intro = colorama.Fore.YELLOW + '''
  ___  ___      ___ ___     _
 |   \|   \ ___/ __| _ \___| |_
 | |) | |) / _ \__ \  _/ _ \  _|
 |___/|___/\___/___/_| \___/\__|

                v%s
''' % (version) + colorama.Style.RESET_ALL + '''


 [+] List enabled honeypots using "list"
 [+] Start honeypot(s) using "start <honeypot>" or "start all"
 [+] Use "help" to list all available commands

'''

    def cmdloop(self, intro=None):
        # avoid exiting the shell with CTRL-C
        # enter another cmdloop instance instead
        try:
            cmd.Cmd.cmdloop(self)
        except KeyboardInterrupt:
            self.intro = ' '
            self.cmdloop()

    def do_list(self, args):
        '''
list
======

Print the list of the available honeypots and corresponding status (enabled/disabled).
'''
        pot_table = []
        for pot in self.pots:
            status = 'ENABLED' if pot['enabled'] else 'DISABLED'
            pot_table.append((
                                pot['name'],
                                pot['desc'],
                                pot['version'],
                                pot['author'],
                                status
                            ))

        print('\nAvailable honeypots:\n')
        print((self._indent(tabulate.tabulate(pot_table, headers=('Name', 'Description', 'Version', 'Author', 'Status')))))

    def do_start(self, args):
        '''
start
======

Usage: start [<honeypot>]

Start honeypot specified as an argument.
If no arguments are specified, start all honeypots configured in global.conf configuration file.
'''
        # filter out incorrectly specified pots first
        if args != '' and args not in self.pot_names:
            utils.print_err('Honeypot "%s" is not available! Please use one of the available honeypots.' % (args))
            self.do_list(None)
            return

        for pot in self.pots:
            if args == '' or args == pot['name']:
                if pot['enabled']:
                    state = pot['plugin'].status()
                    if state == 'Starting' or state == 'Running':
                        utils.print_warn('Honeypot "%s" starting or already running, will not start again' % (pot['name']))
                        continue
                else:
                    # only ask user if the pot name is explicitly specified!
                    if args != '':
                        should_enable = ''
                        while should_enable not in ('y', 'n'):
                            should_enable = input(colorama.Fore.YELLOW + 'Honeypot "%s" is currently disabled - do you want to enable it and start it? [y/n] ' % (args)).lower().strip()

                        # enable the honeypot if user wants so (write it to config also!)
                        if should_enable == 'y':
                            pot['enabled'] = True
                            self.conf.set('honeypots', args, 'True')
                            print(('Enabling "%s"...' % (args)))
                            self._write_config()
                        else:
                            return
                    # skip pot if no pot name has been specified and pot is disabled
                    else:
                        continue

                pot['plugin'].setup()
                pot['thread'] = threading.Thread(target=pot['plugin'].run)
                pot['thread'].start()

    def do_stop(self, args):
        '''
stop
======

Usage: stop [<honeypot>]

Stop honeypot specified as an argument.
If no arguments are specified, stop all currently running honeypots.
'''
        pot_found = True if args == '' else False
        for pot in self.pots:
            if args == '' or args == pot['name']:
                if pot['thread'] is None:
                    continue
                pot_found = True
                pot['plugin'].shutdown()
                pot['thread'].join()
                pot['thread'] = None

        if not pot_found:
            utils.print_err('Honeypot "%s" is not available or not started!' % (args))
            return

    def do_status(self, args):
        '''
status
======

Usage: status <honeypot>

Print running status of the specified honeypot and gather statistics.
If no honeypot is specified, list short status of all currently running honeypots.
'''
        status_table = []
        for pot in self.pots:
            if pot['thread'] is None:
                continue

            # long status for specific honeypot
            # pot status function returns a dict and it must be placed in a list because of tabulate function
            if args == pot['name']:
                detailed_stats = pot['plugin'].status(short=False)
                print(('\n%s status:\n' % (pot['name'])))
                print((self._indent(tabulate.tabulate(self._flatten_stats(detailed_stats)))))
                return

            # if no honeypot has been specified, obtain short status
            elif args == '':
                status_table.append((pot['name'], pot['plugin'].status()))

        if status_table:
            print('\nHoneypot status:\n')
            print((self._indent(tabulate.tabulate(status_table, headers=('Name', 'Status')))))

    def do_exit(self, args):
        '''Exit DDoSPot.'''
        print('Exiting DDoSPot...')
        self.do_stop('')
        sys.exit(0)

    def do_quit(self, args):
        '''Exit DDoSPot.'''
        self.do_exit(args)

    def default(self, line):
        '''Overriden default method in order to show custom error message when command is not recognized.'''
        utils.print_err('Unknown command: %s\n' % (line))
        self.do_help(None)

    def emptyline(self):
        '''When empty line is entered in a prompt, simply do nothing - do not repeat the last command.'''
        pass

    def _flatten_stats(self, stats):
        # iterating through list of lists containing various honeypot stats
        # typical format is [['Stat description', val], ['Stat2 description', val2] ...]
        # if any of the element within the inner list is a tuple, flatten it for tabulate module
        # beware - function assumes stats always have the specified format:
        #   - list with two-element lists
        #   - first element is always non-iterable, second element can be a tuple
        flatten_stats = []
        for stat in stats:
            if isinstance(stat[1], tuple):
                flatten_stats.append([stat[0], ''])
                flatten_stats.extend(['', e] for e in stat[1])
            else:
                flatten_stats.append(stat)
        return flatten_stats

    # see https://bitbucket.org/astanin/python-tabulate/pull-requests/14/indent-option
    def _indent(self, txt, spaces=4):
        indented = '\n'.join(' '*spaces + ln for ln in txt.splitlines())
        return indented + '\n'

    def _read_config(self):
        try:
            self.conf = configparser.RawConfigParser()
            self.conf.read('global.conf')
            honeypots = self.conf.items('honeypots')

            # load all plugin modules here and store all info to pots dict
            loaded_plugins = spf.load_plugins(names=[x[0] for x in honeypots])
            for plugin in self.plugins:
                pot = {}
                name = plugin.name()
                pot['name'] = name
                pot['version'] = loaded_plugins[name].__version__
                pot['desc'] = loaded_plugins[name].__desc__
                pot['author'] = loaded_plugins[name].__author__
                pot['plugin'] = plugin
                pot['thread'] = None
                pot['enabled'] = self.conf.getboolean('honeypots', name)
                self.pots.append(pot)
                self.pot_names.append(name)

            # sort the pot list for convenience
            self.pots = sorted(self.pots, key=lambda k: k['name'])
        except configparser.Error as msg:
            utils.print_err('Error occurred while parsing global configuration file: %s' % msg)
            return

    def _write_config(self):
        with open('global.conf', 'wb') as f:
            self.conf.write(f)
