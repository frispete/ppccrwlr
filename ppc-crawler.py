#! /usr/bin/env python3
"""
Synopsis:

Usage: %(appname)s [-hVvf] [-l log] dir..
       -h, --help           this message
       -V, --version        print version and exit
       -v, --verbose        verbose mode (cumulative)
       -l, --logfile=fname  log to this file
       -f, --force          force operation

Description:
Crawl directories containing supportconfigs for ppc64le cases, and collect some
hardware aspects in order to recognize some regular appearing issues.

(c)2022 by %(company)s
Created by %(author)s

License:
%(license)s
"""
#
# vim:set et ts=8 sw=4:
#

__version__ = '0.1'
__company__ = 'SUSE LLC'
__author__ = 'Hans-Peter Jansen <hp.jansen@suse.com>'
__license__ = 'GNU GPL v2 - see http://www.gnu.org/licenses/gpl2.txt for details'


import os
import re
import sys
import getopt
import pprint
import fnmatch
import logging
import logging.handlers
import functools
from dataclasses import dataclass


class gpar:
    """ Global parameter class """
    appdir, appname = os.path.split(sys.argv[0])
    if appdir == '.':
        appdir = os.getcwd()
    if appname.endswith('.py'):
        appname = appname[:-3]
    version = __version__
    company = __company__
    author = __author__
    license = __license__
    loglevel = logging.INFO
    logfile = None
    force = False
    # internal
    hwfn = 'hardware.txt'
    arch = 'ppc64le'


log = logging.getLogger(gpar.appname)

stdout = lambda *msg: print(*msg, file = sys.stdout, flush = True)
stderr = lambda *msg: print(*msg, file = sys.stderr, flush = True)


class trace:
    """ Trace decorator class """
    def __init__(self, loglevel = logging.DEBUG, maxlen = 20):
        self.loglevel = loglevel
        self.maxlen = maxlen

    def abbrev(self, arg):
        if arg:
            argstr = repr(arg)
            if len(argstr) > self.maxlen:
                argstr = argstr[:self.maxlen] + "..'"
            return argstr
        return arg

    def argstr(self, *args, **kwargs):
        arglist = []
        for arg in args:
            if arg:
                arglist.append(self.abbrev(arg))
        for k, v in kwargs.items():
            arglist.append('{} = {}'.format(k, self.abbrev(v)))
        return ', '.join(arglist)


    def __call__(self, func):
        @functools.wraps(func)
        def trace_and_call(*args, **kwargs):
            result = func(*args, **kwargs)
            argstr = self.argstr(*args, **kwargs)
            logging.log(self.loglevel, '{}({}): {}'.format(func.__name__, argstr, result))
            return result
        return trace_and_call


def exit(ret = 0, msg = None, usage = False):
    """ Terminate process with optional message and usage """
    if msg:
        stderr('%s: %s' % (gpar.appname, msg))
    if usage:
        stderr(__doc__ % gpar.__dict__)
    sys.exit(ret)


def setup_logging(logfile, loglevel):
    """ Setup various aspects of logging facility """
    logconfig = dict(
        level = loglevel,
        format = '%(asctime)s %(levelname)5s: [%(name)s] %(message)s',
        datefmt = '%Y-%m-%d %H:%M:%S',
    )
    if logfile not in (None, '-'):
        logconfig['filename'] = logfile
    logging.basicConfig(**logconfig)


def frec(rec, withunderscores = True, indent = None):
    """ format a dict in a sorted, easy to read record presentation
        Note: only string types are allowed as keys
        eg.:
        def __repr__(self):
            return '%s(\n%s\n)' % (self.__class__.__name__, frec(self.__dict__))
    """
    ret = []
    if withunderscores:
        keys = [key for key in rec]
    else:
        keys = [key for key in rec if not key.startswith('_')]
    maxklen = len(keys) and max([len(key) for key in keys]) or 0
    if indent is not None:
        maxklen = max(maxklen, indent)
    for key in keys:
        val = pprint.pformat(rec[key], width = 100)
        valind = '\n%*s' % (maxklen + 2, ' ')
        val = valind.join(val.split('\n'))
        ret.append('%*s: %s' % (maxklen, key, val))
    return '\n'.join(ret)


def fnfind(pattern, path, follow_symlinks = True):
    """ return all files with names matching pattern recursively """
    try:
        for de in os.scandir(path):
            if de.is_dir(follow_symlinks = follow_symlinks):
                for fn in fnfind(pattern, de.path, follow_symlinks):
                    yield fn
            if de.is_file(follow_symlinks = follow_symlinks) and fnmatch.fnmatch(de.name, pattern):
                yield de.path
    except OSError as e:
        log.error(e)


def grep(regexp, lines, max_result = 0):
    """ grep through a list of lines and return first match """
    result = []
    for line in lines:
        mo = re.search(regexp, line)
        if mo:
            result.append(line)
            if max_result and len(result) >= max_result:
                break
    if max_result == 1 and result:
        result = result[0]
    log.debug(f'grep("{regexp}", lines, {max_result}): "{result}"')
    return result


def grep_kv(key, lines, max_result = 0):
    """ simplified grep, that locates key anchored at start of line,
        followed by a colon, and return the value, ignoring white space in between
    """
    result = []
    for line in lines:
        mo = re.match(f'^{key}\s*:\s*(.*)$', line)
        if mo:
            result.append(mo.group(1))
            if max_result and len(result) >= max_result:
                break
    if max_result == 1 and result:
        result = result[0]
    return result


def extract_lines(start_tag, end_tag, lines):
    """ extract lines between start and end tag """
    result = []
    match = False
    for line in lines:
        if not match:
            if re.match(start_tag, line):
                match = True
        else:
            if re.match(end_tag, line):
                match = False
            else:
                result.append(line)
    return result


def extract_command(command, lines):
    """ extract output of a command up to an empty line
        # cmd
        output
        ^$
        returns a str, if output is just one line, and a list otherwise
    """
    result = extract_lines(f'^#\ {command}$', '^$', lines)
    if len(result) == 1:
        result = result.pop()
    return result


def unquote(val, quotes = '\'"'):
    """ unquote string """
    for quote in quotes:
        if val[0] == quote and val[-1] == quote:
            val = val[1:-1]
    return val


def assign_exp_dict(lines, lowercase = False, comment_skip = '#'):
    """ return a dict with key value pairs from lines similar to
        var="val"
    """
    d = {}
    for line in lines:
        if comment_skip and line.startswith(comment_skip):
            continue
        try:
            var, val = line.split('=', maxsplit = 1)
        except ValueError:
            log.error(f'assign_exp_dict: invalid line: {line}')
        else:
            val = unquote(val)
            if lowercase:
                var = var.lower()
            d[var] = val
    log.debug(f'assign_exp_dict({lines}, {lowercase}, {comment_skip}): "{d}"')
    return d


@dataclass(init = False)
class IRQ:
    """ Represent an IRQ, interpret a line similar to:
        [irq:]0 19 (1022323346) "655362 Edge      eth0"
        the part is brackets is filtered in calling class
    """
    nr: int
    count: int
    name: str
    desc: str
    dist: float = 0.0

    def __init__(self, line):
        log.debug(f'IRQ({line})')
        mo = re.match('\d+\s+(?P<nr>\d+)\s+\(\s*(?P<count>\d+)\)\s+"(?P<desc>.*)"', line)
        if mo:
            gd = mo.groupdict()
            for key, mod in (
                ('nr', int),
                ('count', int),
                ('desc', str)
            ):
                setattr(self, key, mod(gd[key]))
            try:
                _, _, self.name = self.desc.split(maxsplit = 2)
            except ValueError:
                self.name = 'undef.'


@dataclass(init = False)
class PPC:
    date: str
    hostname: str
    kernel: str
    os_ver: str
    cpu_count: int
    cpu_type: str
    model: str
    machine: str
    platform: str
    irq: dict
    fw_lvl: str
    fw_dat: str
    fw_img: str
    path: str

    """ Represent hardware details of a PPC64LE machine """
    def __init__(self, fn):
        self.path = os.path.dirname(fn)
        self.lookup_basic_env()
        lines = open(fn, encoding = 'utf-8', errors = 'surrogateescape').read().splitlines()
        cpus = list(grep_kv('cpu', lines))
        self.cpu_count = len(cpus)
        self.cpu_type = {cpu for cpu in cpus}
        self.model = grep_kv('model', lines, 1)
        self.machine = grep_kv('machine', lines, 1)
        self.platform = grep_kv('platform', lines, 1)
        self.irq = {}
        irq_res = grep_kv('irq', lines)
        for irq_des in irq_res:
            irq = IRQ(irq_des)
            if irq.name.startswith('eth'):
                self.irq[irq.nr] = irq
        procirq = extract_lines('----- /proc/interrupts -----',
                                '----- /proc/interrupts end -----', lines)
        for irq in self.irq.values():
            if irq.name.startswith('eth'):
                irq_line = grep(f'^\s+{irq.nr}:', procirq, 1)
                if irq_line:
                    self.irq_dist(irq, irq_line)

        self.lookup_firmware(lines)


    def irq_dist(self, irq, line):
        """ interpret irq distribution from a line similar to:
            irq.nr: <array of irqcount/cpu> irq.desc
                25:  505420892          0.. XICS 655368 Edge      eth0
            return a number 0..100, that represents the interrupt distribution
            values towards 0 and poor, towards 100 are good

            if 0 < irq/cpu <= 2*irqavg: contribute to irqdist factor
        """
        try:
            nr, *irqs, desc = line.split(maxsplit = self.cpu_count + 1)
        except ValueError:
            log.error(f'/proc/interrupts line malformed: {line}')
            return None
        else:
            irqdist = 0.0
            log.debug('irqs: %s', list(irqs))
            irqs = list(map(int, irqs))
            irqcount = sum(irqs)
            irqavg = irqcount/self.cpu_count
            cpuf = 100/self.cpu_count
            log.debug('irqs: %s', irqs)
            log.debug('irqcount (rec.): %s', irq.count)
            log.debug('irqcount (calc): %s', irqcount)
            log.debug('irqcount (avg.): %s', irqavg)
            for ic in irqs:
                if 0 < ic <= 2 * irqavg:
                    irqdist += (ic / irqavg) * cpuf
            irqdist = round(irqdist, 1)
            irq.dist = irqdist
            log.debug('irqcount (dist): %s', irqdist)

    def lookup_firmware(self, lines):
        for var, tag in (
            ('fw_lvl', 'Microcode Level.(ML)'),
            ('fw_dat', 'Microcode Build Date.(MG)'),
            ('fw_img', 'Micro Code Image.(MI)'),
        ):
            tag = re.escape(tag)
            line = grep(f'^\s+{tag}', lines, 1)
            if line:
                mo = re.match(f'^\s+{tag}\.+(.*)$', line)
                if mo:
                    setattr(self, var, mo.group(1))

    def lookup_basic_env(self):
        fn = os.path.join(self.path, 'basic-environment.txt')
        if not os.path.exists(fn):
            return
        lines = open(fn, encoding = 'utf-8', errors = 'surrogateescape').read().splitlines()
        date = extract_command('/bin/date', lines)
        if date:
            self.date = date
        uname = extract_command('/bin/uname -a', lines)
        if uname:
            _, self.hostname, self.kernel, _ = uname.split(maxsplit = 3)
        osrel = extract_command('/etc/os-release', lines)
        if osrel:
            d = assign_exp_dict(osrel, True)
            self.os_ver = "{name} {version}".format(**d)

    def __str__(self):
        return '%s(\n%s\n)' % (self.__class__.__name__, frec(self.__dict__))


@trace()
def process(args):
    ret = 0
    log.debug('started with pid %s in %s', os.getpid(), gpar.appdir)

    for path in args:
        log.debug(f'search {path}')
        for fn in fnfind(gpar.hwfn, path):
            log.debug(f'examine {fn}')
            # optimization: we just read line by line, until we hit
            # Architecture line. This avoids reading the whole file,
            # if it's not the one, we're looking for..
            for line in open(fn, encoding = 'utf-8'):
                if gpar.arch in grep_kv('Architecture', [line]):
                    print(PPC(fn))
                    print()
                    break

    return ret


def main(argv = None):
    """Command line interface and console script entry point."""
    if argv is None:
        argv = sys.argv[1:]

    try:
        optlist, args = getopt.getopt(argv, 'hVvl:f',
            ('help', 'version', 'verbose', 'logfile=',
             'force')
        )
    except getopt.error as msg:
        exit(1, msg, True)

    for opt, par in optlist:
        if opt in ('-h', '--help'):
            exit(usage = True)
        elif opt in ('-V', '--version'):
            exit(msg = 'version %s' % gpar.version)
        elif opt in ('-v', '--verbose'):
            if gpar.loglevel > logging.DEBUG:
                gpar.loglevel -= 10
        elif opt in ('-l', '--logfile'):
            gpar.logfile = par
        elif opt in ('-f', '--force'):
            gpar.force = True

    setup_logging(gpar.logfile, gpar.loglevel)

    try:
        return process(args)
    except KeyboardInterrupt:
        return 3    # SIGQUIT


if __name__ == '__main__':
    sys.exit(main())

