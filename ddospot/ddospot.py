#!/usr/bin/env python3

import argparse
import signal
import sys

import core.console as console
import core.utils as utils

__version__ = "1.0.0.dev"


def main():
    # in both modes, cmd subclass will be created, but for non-interactive mode, cmdloop won't be started
    # call do_start method directly for non-interactive mode (small hack)
    prog = console.DDoSPot(__version__)

    # declaring handle in main scope in order to have prog object available
    def handle_interrupt(signal, frame):
        print('')
        utils.print_warn('CTRL-C pressed, exiting DDoSPot...')
        prog.do_stop('')
        sys.exit(0)

    parser = argparse.ArgumentParser()
    parser.add_argument(
                        '-n',
                        '--non-interactive',
                        help='Non-interactive mode. By default, DDoSPot is started in interactive console mode.',
                        action='store_true'
                        )
    args = parser.parse_args()

    if args.non_interactive:
        utils.print_succ('\n====== DDoSPot - non-interactive mode ======\n')
        prog.do_start('')

        # register keyboard interrupt handler - script won't exit until CTRL+C is pressed
        signal.signal(signal.SIGINT, handle_interrupt)
        signal.pause()
    else:
        prog.cmdloop()

if __name__ == "__main__":
    main()
