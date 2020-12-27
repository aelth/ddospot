#!/usr/bin/env python3

try:
    import colorama
except ImportError:
    exit('Please install colorama for colorful console output: pip install colorama')


def print_err(msg):
    print((colorama.Fore.RED + '[-] ' + msg))


def print_warn(msg):
    print((colorama.Fore.YELLOW + '[!] ' + msg))


def print_succ(msg):
    print((colorama.Fore.GREEN + msg))


def addr_to_int(addr):
    if addr:
        return int('{:02X}{:02X}{:02X}{:02X}'.format(*list(map(int, addr.split('.')))), 16)
    else:
        return 0


def int_to_addr(addr_int):
    if addr_int:
        return '.'.join(str(addr_int >> i & 0xFF) for i in (24, 16, 8, 0))
    else:
        return '-'


# see https://stackoverflow.com/questions/538666/python-format-timedelta-to-string
def format_timedelta(td):
    seconds = int(td.total_seconds())
    periods = [
            ('day',         86400),
            ('hour',        3600),
            ('minute',      60),
            ('second',      1)
              ]

    strings=[]
    for period_name,period_seconds in periods:
        if seconds > period_seconds:
            period_value, seconds = divmod(seconds, period_seconds)
            if period_value == 1:
                strings.append('%s %s' % (period_value, period_name))
            else:
                strings.append('%s %ss' % (period_value, period_name))

    return ', '.join(strings)


# see https://stackoverflow.com/questions/1094841/reusable-library-to-get-human-readable-version-of-file-size
def format_unit(num):
    for unit in ['B','KB','MB','GB','TB']:
        if abs(num) < 1024.0:
            return '%3.2f %s' % (num, unit)
        num /= 1024.0
    return '%.1f PB' % (num)


def sep_thousand(val):
    return '{:,}'.format(val)
