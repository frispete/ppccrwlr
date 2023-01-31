#! /usr/bin/env python3
"""
Synopsis: Exermine supportconfigs for PPC specific issues

Usage: {appname} [-hVvf] [-l log] dir..
       -h, --help           this message
       -V, --version        print version and exit
       -v, --verbose        verbose mode (cumulative)
       -l, --logfile=fname  log to this file
       -f, --force          force operation

Description:
Crawl directories containing supportconfigs for {arch} cases, and collect some
setup and hardware configuration aspects in order to recognize and analyse a
couple of regular appearing issues.

Copyright: (c)2022-2023 {company}
Created by: {author}
License: {license}
"""
#
# vim:set et ts=8 sw=4:
#

__version__ = '0.2'
__company__ = 'SUSE LLC'
__author__ = 'Hans-Peter Jansen <hp.jansen@suse.com>'
__license__ = 'GNU GPL v2 - see http://www.gnu.org/licenses/gpl2.txt for details'


import os
import re
import sys
import time
import getopt
import pprint
import fnmatch
import logging
import datetime
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
    loglevel = logging.WARNING
    logfile = None
    force = False
    # internal
    befn = 'basic-environment.txt'
    hwfn = 'hardware.txt'
    memfn = 'memory.txt'
    lparfn = os.path.join('ppc64', 'lparcfg')
    encoding = 'utf-8'
    arch = 'ppc64le'


log = logging.getLogger(gpar.appname)

# add a new loglevel below DEBUG (10) and NOTSET (0)
logging.TRACE = 5
logging.addLevelName(logging.TRACE, 'TRACE')

def _trace(self, message, *args, **kws):
    self.log(logging.TRACE, message, *args, **kws)
logging.Logger.trace = _trace


stdout = lambda *msg: print(*msg, file = sys.stdout, flush = True)
stderr = lambda *msg: print(*msg, file = sys.stderr, flush = True)


def exit(ret = 0, msg = None, usage = False):
    """ Terminate process with optional message and usage """
    if msg:
        stderr(f'{gpar.appname}: {msg}')
    if usage:
        stderr(__doc__.format(**gpar.__dict__))
    sys.exit(ret)


def setup_logging(logfile, loglevel):
    """ Setup various aspects of logging facility """
    logconfig = dict(
        level = loglevel,
        format = '%(asctime)s %(levelname)5s: %(message)s',
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


def fsizeof(value, digit = 1, suffix = 'B'):
    """ return a human readable binary size of value """
    value = float(value)
    for unit in ('', 'Ki', 'Mi', 'Gi', 'Ti', 'Pi', 'Ei', 'Zi'):
        if abs(value) < 1024.0:
            return f'{value:3.{digit}f} {unit}{suffix}'
        value /= 1024.0
    # cap at yotta
    return f'{value:.{digit}f} Yi{suffix}'


def fdeltat(td, short = False, fuzzy = False):
    """ return a human readable representation of timedelta, int or float values
        int or float values are expected to be the number of seconds already
        if fuzzy is true, just return the first value
    """
    rv = []
    if isinstance(td, datetime.timedelta):
        td = td.total_seconds()
    hours, minutes = 0, 0
    secs, fraction = divmod(td, 1)
    secs = int(secs)
    if secs >= 60:
        # ignore fractional part, if dt is >= 1 min
        fraction = 0
    else:
        # convert to msecs
        fraction *= 1000

    for singular, plural, period in (
        ('year',    'years',    60 * 60 * 24 * 365),
        ('month',   'months',   60 * 60 * 24 * 30),
        ('week',    'weeks',    60 * 60 * 24 * 7),
        ('day',     'days',     60 * 60 * 24),
        ('hour',    'hours',    60 * 60),
        ('minute',  'minutes',  60),
        ('second',  'seconds',  1),
    ):
        if secs > period or period == 1:
            val, secs = divmod(secs, period)
            if short:
                if period > 60 * 60:
                    rv.append('%s%s' % (val, singular[0]))
                elif period == 60 * 60:
                    hours = val
                elif period == 60:
                    minutes = val
                elif period == 1:
                    if fraction:
                        val = '%d.%03d' % (val, fraction)
                    else:
                        val = '%02d' % (val)
            else:
                if period == 1 and fraction:
                    val = '%d.%03d' % (val, fraction)
                if val == 1:
                    rv.append('%s %s' % (val, singular))
                else:
                    rv.append('%s %s' % (val, plural))
                if fuzzy:
                    break

    if short:
        return ''.join(rv) + '%02d:%02d:%s' % (hours, minutes, val)
    else:
        # in 1 hour, 33 minutes, 12 seconds
        # -> 1 hour, 33 minutes and 12 seconds
        return ' and '.join(', '.join(rv).rsplit(', ', 1))


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
    log.trace(f'assign_exp_dict({lines}, {lowercase}, {comment_skip}): "{d}"')
    return d


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


class TFS:
    """ TextFileSearch """
    def __init__(self, fn, encoding = 'utf-8', errors = 'surrogateescape'):
        try:
            self._lines = open(fn, encoding = encoding, errors = errors).read().splitlines()
        except OSError as e:
            log.error(e)
        else:
            self._fn = fn

    def search(self, regexp, max_result = 0, lines = None):
        """ search the file and return a list of matches up to max_result
            * if max_result is not 1, the result is returned as a list, and
              unpacked from the list, if it is 1 and there's a match
            * if lines is None, search self._lines
            * if the regexp contains named grouping elements, the grouping
              dict is returned, unnamed grouping as a tuple and the matching
              line otherwise
        """
        def collect_result(mo):
            ret = mo.groupdict()
            if not ret:
                ret = mo.groups()
                if not ret:
                    ret = mo.group()
            return ret

        result = []
        if lines is None:
            lines = self._lines
        for line in lines:
            mo = re.search(regexp, line)
            if mo:
                result.append(collect_result(mo))
                if max_result and len(result) >= max_result:
                    break
        if max_result == 1 and result:
            result = result[0]
        log.trace(f'TFS.search("{regexp}", max_result: {max_result}): "{result}"')
        return result

    def match_key(self, key, max_result = 0, lines = None, defval = None, sep = ':'):
        """ find matches of a space padded key, and return the value part,
            separated with sep and return a list of matches up to max_result
            * if lines is None, search self._lines
            * if max_result is not 1, the result is returned as a list, and
              unpacked from the list, if it is 1 and there's a match
        """
        result = []
        if lines is None:
            lines = self._lines
        for line in lines:
            mo = re.match(f'^\s*{key}\s*{sep}\s*(?P<match>.*)$', line)
            if mo:
                result.append(mo['match'])
                if max_result and len(result) >= max_result:
                    break
        if max_result == 1 and result:
            result = result[0]
        if result == []:
            result = defval
        log.trace(f'TFS.match_key("{key}", max_result: {max_result}, sep: "{sep}"): "{result}"')
        return result

    def extract_lines(self, start_tag, end_tag, offset = 0, lines = None):
        """ extract lines between start and end tag, starting at offset
            return a list of extracted lines and the current offset, suitable
            for continuinng the operation
        """
        result = []
        if lines is None:
            lines = self._lines
        lnr = 0
        match = False
        if offset < len(lines):
            for lnr, line in enumerate(lines):
                # fast forward
                if lnr < offset:
                    continue
                log.trace(f'{lnr}: "{line}"')
                # start the search
                if not match:
                    if re.match(start_tag, line):
                        # found a match
                        match = True
                else:
                    if re.match(end_tag, line):
                        # hit the end tag
                        match = False
                        # stop the search
                        break
                    else:
                        # collect result
                        result.append(line)
            # prepare for continuation
            lnr += 1
        log.trace(f'TFS.extract_lines("{start_tag}", "{end_tag}", offset: {offset}): {result}, {lnr}')
        return result, lnr

    def extract_command(self, command, double_blank = False, lines = None):
        """ extract output of a command up to an blank line
            if double_blank is True, the output is terminated with two consecutive blank lines
            # cmd
            output
            ^$
            returns a str, if output is just one line, and a list otherwise
        """
        if lines is None:
            lines = self._lines
        result, offset = self.extract_lines(f'^#\ {command}$', '^$', 0, lines)
        if double_blank:
            while True:
                result.append('')
                if lines[offset]:
                    # next line not blank, start on last blank line
                    output, offset = self.extract_lines('^$', '^$', offset-1, lines)
                    result.extend(output)
                else:
                    # two consecutive blank lines: finished
                    break
        if len(result) == 1:
            result = result.pop()
        log.trace(f'TFS.extract_command("{command}", double_blank: {double_blank}): {result}')
        return result

    def __repr__(self):
        return f'{self.__class__.__name__}({self._fn})'


@dataclass
class IRQ:
    """ Represent an IRQ, parse a line similar to:
        [irq:]0 19 (1022323346) "655362 Edge      eth0"
        the part is brackets is filtered in calling class
    """
    nr: int
    count: int
    name: str
    model: str = ''
    dist: float = 0.0

    def __init__(self, line):
        log.debug(f'IRQ({line})')
        mo = re.match('\d+\s+(?P<nr>\d+)\s+\(\s*(?P<count>\d+)\)\s+"(?P<desc>.*)"', line)
        if mo:
            gdict = mo.groupdict()
            for key, mod in (
                ('nr', int),
                ('count', int),
                ('desc', str)
            ):
                setattr(self, key, mod(gdict[key]))
                if key == 'desc':
                    log.debug(f'desc: {self.desc}')
            try:
                _, _, self.name = self.desc.split(maxsplit = 2)
            except ValueError:
                self.name = 'undef.'


@dataclass
class NIC:
    """ Represent an NIC, parsed from lines similar to:
        21: Virtual IO 00.0: 0200 Ethernet controller
        [...]
          Model: "IBM Virtual Ethernet card 0"
          Vendor: int 0x6001 "IBM"
          Device: "Virtual Ethernet card 0"
          Driver: "ibmveth"
          Driver Modules: "ibmveth"
          Device File: eth0
          PROM id: vdevice/l-lan@30000002
          HW Address: 72:b5:18:50:43:02
          Permanent HW Address: 72:b5:18:50:43:02
          Link detected: yes
          Module Alias: "vio:TnetworkSIBM,l-lan"
          Driver Info #0:
            Driver Status: ibmveth is active
            Driver Activation Cmd: "modprobe ibmveth"
          Config Status: cfg=no, avail=yes, need=no, active=unknown
        ^$
    """
    model: str
    driver: str
    device: str
    hwaddr: str
    hwaddrp: str
    link: bool

    def __init__(self, tfs, lines):
        log.trace(f'NIC({tfs})')
        for label, key, mod in (
            ('Model', 'model', unquote),
            ('Driver', 'driver', unquote),
            ('Device File', 'device', str),
            ('HW Address', 'hwaddr', str),
            ('Permanent HW Address', 'hwaddrp', str),
            ('Link detected', 'link', bool),
        ):
            val = tfs.match_key(f'{label}', 1, lines)
            setattr(self, key, mod(val))


onoff_dict = {
    -1: 'UNDEF',
    0: 'OFF',
    1: 'ON',
}

class PPCError(Exception):
    """ PPCErrors are raised from fatal parse errors """

@dataclass
class PPC:
    date: str
    hostname: str
    kernel: str
    os_ver: str
    memory: str
    shared_cpus: str
    cpu_count: int
    cpu_type: str
    model: str
    machine: str
    platform: str
    irq: dict
    nic: dict
    fw_lvl: str
    fw_dat: str
    fw_img: str
    path: str

    """ Represent hardware details of a PPC64LE machine """
    def __init__(self, fn):
        self.path = os.path.dirname(fn)
        self.lookup_basic_env()
        self.lookup_memory()
        self.lookup_lparcfg()
        tfs = TFS(fn)
        cpulist = tfs.extract_command('/proc/cpuinfo', double_blank = True)
        log.debug(f'{cpulist}')
        cpus = list(tfs.match_key('cpu', lines = cpulist))
        log.debug(f'{cpus}')
        self.cpu_count = len(cpus)
        self.cpu_type = {cpu for cpu in cpus}
        self.model = tfs.match_key('model', 1)
        self.machine = tfs.match_key('machine', 1)
        self.platform = tfs.match_key('platform', 1)
        self.irq = {}
        self.nic = {}
        irq_res = tfs.match_key('irq')
        for irq_des in irq_res:
            irq = IRQ(irq_des)
            if irq.name.startswith('eth'):
                self.irq[irq.nr] = irq
        procirq, _ = tfs.extract_lines('----- /proc/interrupts -----',
                                       '----- /proc/interrupts end -----')
        for irq in self.irq.values():
            if irq.name.startswith('eth'):
                irq_line = tfs.match_key(f'{irq.nr}', 1, procirq)
                if irq_line:
                    self.irq_dist(irq, irq_line)

        self.lookup_nic(tfs)
        self.lookup_firmware(tfs)

    def irq_dist(self, irq, line):
        """ determine irq distribution from a line similar to:
            <array of irqcount/cpu> irq.desc
             505420892          0.. XICS 655368 Edge      eth0
            return a number 0..100, that represents the interrupt distribution
            values towards 0 are poor, towards 100 are good

            if 0 < irq/cpu <= 2*irqavg: contribute to irqdist factor

            if one cpu runs more than twice the average number of interrupts,
            it's count is discarded
            while at it, extract irq model: XICS or XIVE
        """
        log.debug(f'irq_dist({irq}, "{line}"), cpu_count: {self.cpu_count}')
        try:
            *irqs, desc = line.split(maxsplit = self.cpu_count)
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
            log.debug(f'irq: {irq.nr}: {irqs}, total {irqcount}')
            log.debug(f'irqcount (avg.): {irqavg:.1f}, cpu factor: {cpuf:.2f}')
            if irq.count != irqcount:
                log.warning(f'irq({irq.nr}): {irq.count:_} (rec) != {irqcount:_} (calc): interrupt count inconsistent')
            for ic in irqs:
                if 0 < ic <= 2 * irqavg:
                    irqdist += (ic / irqavg) * cpuf
            irqdist = round(irqdist, 1)
            irq.dist = irqdist
            log.debug(f'irq distribution: {irqdist}')
            # extract interrupt model
            im, _ = desc.split(maxsplit = 1)
            if im == 'XIVE-IRQ':
                im = 'XIVE'
            if im not in ('XICS', 'XIVE'):
                log.warning(f'irq: {irq.nr}: unknown interrupt model: {im}')
            irq.model = im
            log.debug(f'irq: {irq.nr}: interrupt model: {im}')

    def lookup_nic(self, tfs):
        """ collect all nics """
        offset = 0
        while True:
            niclines, offset = tfs.extract_lines('\d+: .* 0200 Ethernet controller$',
                                                 '^$', offset)
            log.debug(f'lookup_nic(offset: {offset})')
            if niclines:
                nic = NIC(tfs, niclines)
                self.nic[nic.device] = nic
            else:
                break

    def lookup_firmware(self, tfs):
        """ fetch firmware values """
        for var, tag in (
            ('fw_lvl', 'Microcode Level.(ML)'),
            ('fw_dat', 'Microcode Build Date.(MG)'),
            ('fw_img', 'Micro Code Image.(MI)'),
        ):
            tag = re.escape(tag)
            result = tfs.search(f'^\s+{tag}\.+(?P<value>.*)$', 1)
            if result:
                setattr(self, var, result['value'])

    def lookup_lparcfg(self):
        """ examine ppc64/lparcfg """
        fn = os.path.join(self.path, gpar.lparfn)
        if not os.path.exists(fn):
            log.warning(f'{fn} not found')
        else:
            tfs = TFS(fn)
            try:
                spm = int(tfs.match_key('shared_processor_mode', 1, defval = -1, sep = '='))
            except Exception as e:
                log.exception(e)
            else:
                self.shared_cpus = onoff_dict.get(spm, 'UNKNOWN')

    def lookup_basic_env(self):
        """ fetch general parameter from basic environment """
        fn = os.path.join(self.path, gpar.befn)
        if not os.path.exists(fn):
            return
        tfs = TFS(fn)
        date = tfs.extract_command('/bin/date')
        if date:
            self.date = date
        uname = tfs.extract_command('/bin/uname -a')
        if uname:
            _, self.hostname, self.kernel, _ = uname.split(maxsplit = 3)
        osrel = tfs.extract_command('/etc/os-release')
        if osrel:
            d = assign_exp_dict(osrel, True)
            self.os_ver = "{name} {version}".format(**d)

    def lookup_memory(self):
        fn = os.path.join(self.path, gpar.memfn)
        if not os.path.exists(fn):
            raise PPCError(f'{fn} not found')
        tfs = TFS(fn)
        meminfo = tfs.extract_command('/proc/meminfo')
        log.debug(f'meminfo: {meminfo}')
        # Memory in GB
        mem = tfs.match_key('MemTotal', 1, meminfo)
        if mem.endswith(' kB'):
            mem = mem[:-3]
        try:
            mem = int(mem)
        except ValueError:
            log.warning('invalid MemTotal value from /proc/meminfo')
        else:
            self.memory = f'{fsizeof(mem * 1024, 2)} [{mem:,} KiB]'
        log.debug(f'memory: {self.memory}')

    def __str__(self):
        return '%s(\n%s\n)' % (self.__class__.__name__, frec(self.__dict__))


def process(args):
    started = time.time()
    scnr = 0
    ret = 0
    log.debug('started with pid %s in %s', os.getpid(), gpar.appdir)

    for path in args:
        log.debug(f'search {path}')
        for fn in fnfind(gpar.hwfn, path, False):
            log.debug(f'examine {fn}')
            # optimization: we just read line by line, until we hit
            # Architecture line. This avoids reading the whole file,
            # if it's not the one, we're looking for..
            for line in open(fn, encoding = 'utf-8'):
                if line.startswith('Architecture'):
                    if gpar.arch in line.split():
                        ppc = PPC(fn)
                        ll = log.getEffectiveLevel()
                        log.setLevel(logging.INFO)
                        log.info(str(ppc) + '\n')
                        log.setLevel(ll)
                        scnr += 1
                    break

    log.info('%s supportconfigs examined in %s', scnr, fdeltat(time.time() - started))

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
            exit(msg = 'version {}'.format(gpar.version))
        elif opt in ('-v', '--verbose'):
            if gpar.loglevel > logging.DEBUG:
                gpar.loglevel -= 10
            elif gpar.loglevel == logging.DEBUG:
                gpar.loglevel = logging.TRACE
        elif opt in ('-l', '--logfile'):
            gpar.logfile = par
        elif opt in ('-f', '--force'):
            gpar.force = True

    if not args:
        exit(usage = True)

    setup_logging(gpar.logfile, gpar.loglevel)

    try:
        return process(args)
    except SystemExit as e:
        return e.code
    except KeyboardInterrupt:
        return 5
    except:
        log.exception('internal error:')
        return 8


if __name__ == '__main__':
    sys.exit(main())

