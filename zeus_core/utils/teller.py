import sys
from time import time


class TellerStream(object):

    def __init__(self, outstream=None, output_interval_ms=2000,
                 buffering=1, buffer_feeds=0):
        self.oms = output_interval_ms
        self.outstream = outstream
        self.last_output = 0
        self.last_eject = 0
        self.buffer_feeds = buffer_feeds
        self.buffering = buffering
        self.buffered_lines = []

    def write(self, data):
        buffer_feeds = self.buffer_feeds
        eject = not buffer_feeds and (1 if '\n' in data else 0)
        if not self.buffering:
            self.buffered_lines = []
        self.buffered_lines.append(data)

        t = time()
        tdiff = (t - self.last_output) * 1000.0

        if eject or self.last_eject or tdiff > self.oms:
            self.last_output = t
            self.flush()

        self.last_eject = eject

    def flush(self):
        outstream = self.outstream
        if outstream:
            outstream.write(''.join(self.buffered_lines))
        self.buffered_lines = []


class Teller(object):
    name = None
    total = None
    current = None
    finished = None
    status_fmt = None
    status_args = None
    start_time = None
    disabled = False
    children = None
    parent = None
    resuming = None
    outstream = None
    last_active = None
    last_teller = [None]
    last_ejected = [None]
    last_line = ['']

    redirect = True
    fail_parent = True
    raise_errors = True
    default_tell = True
    suppress_exceptions = False
    default_status_fmt = '%d/%d'

    eol             =   '\r'
    feed            =   '\n'
    prefix_filler   =   '|  '
    status_sep      =   ' ... '

    start_mark      =   '-- '
    pending_mark    =   '|  '
    notice_mark     =   '|  :: '
    fail_mark       =   '!! '
    finish_mark     =   '++ '

    start_status    =   '      '
    pending_status  =   '      '
    fail_status     =   '*FAIL*'
    finish_status   =   ' -OK- '

    def __init__(self, name='', total=1, current=0, depth=0,
                 parent=None, resume=False, subtask=False,
                 outstream=sys.stderr, **kw):
        if subtask and parent:
            name = str(parent) + '/' + name
            self.feed = ''
        self.name = name
        self.depth = depth
        self.total = total
        self.current = current
        self.clear_size = 0
        self.parent = parent
        self.children = {}
        self.set_format()
        self.resuming = resume
        self.outstream = outstream
        self.start_time = time()

        for k, v in kw.items():
            a = getattr(self, k, None)
            if (a is None and not (isinstance(a, basestring)
                                   or isinstance(a, bool))):
                continue
            setattr(self, k, v)

    def set_format(self):
        current = self.current
        total = self.total
        if total == 1:
            self.status_fmt = ''
            self.status_args = ()
            return

        self.status_fmt = self.default_status_fmt
        self.status_args = (current, total)

    def kill_child(self, child_id):
        children = self.children
        if child_id in children:
            del children[child_id]

    def __str__(self):
        total = self.total
        current = self.current
        status_fmt = self.status_fmt
        if status_fmt is None:
            self.set_format()
            status_fmt = self.status_fmt

        start_time = self.start_time
        running_time = time() - start_time

        finished = self.finished
        if finished is None:
            mark = self.start_mark
            status = self.start_status
        elif finished > 0:
            mark = self.finish_mark
            status = self.finish_status
        elif finished < 0:
            mark = self.fail_mark
            status = self.fail_status
        elif finished == 0:
            mark = self.pending_mark
            status = self.pending_status
        else:
            m = "Finished not None or int: %r" % (finished,)
            raise ValueError(m)

        line = (self.prefix_filler * (self.depth - 1)) + mark
        line += self.name + self.status_sep
        line += self.status_fmt % self.status_args
        line += status
        if running_time > 2 and current > 0 and current < total:
            ss = running_time * (total - current) / current
            mm = ss / 60
            ss = ss % 60
            hh = mm / 60
            mm = mm % 60
            line += 'approx. %02d:%02d:%02d left' % (hh, mm, ss)
        return line

    def disable(self):
        self.disabled = True
        for child in self.children.values():
            child.disable()

    def tell(self, feed=False, eject=False):
        if self.disabled:
            return

        line = self.__str__()
        self.output(line, feed=feed, eject=eject)

    def output(self, text, feed=False, eject=0):
        outstream = self.outstream
        if outstream is None or self.disabled:
            return

        feeder = self.feed
        eol = self.eol
        text += eol
        last_line = self.last_line
        if eol.endswith('\r'):
            clear_line = ' ' * len(last_line[0]) + '\r'
        else:
            clear_line = ''
        text = clear_line + text

        last_teller = self.last_teller
        teller = last_teller[0]
        last_ejected = self.last_ejected
        ejected = last_ejected[0]
        if not ejected and (feed or teller != self):
            text = feeder + text
        if eject:
            text += feeder * eject

        outstream.write(text)
        last_teller[0] = self
        last_ejected[0] = eject
        junk, sep, last = text.rpartition('\n')
        last_line[0] = last[len(clear_line):]

    def check_tell(self, tell, feed=False, eject=False):
        if tell or (tell is None and self.default_tell):
            self.tell(feed=feed, eject=eject)

    def active(self):
        if not self.redirect:
            return self

        last_active = self.last_active
        if (last_active is not None
            and last_active == self.last_teller[0]
                and not last_active.disabled):
            return last_active

        while 1:
            children = self.children
            if not children:
                return self

            if len(children) != 1:
                m = ("Cannot redirect: more than one children are active! "
                     "Either start one children at a time, "
                     "or set redirect=False")
                raise ValueError(m)

            self, = children.values()

        return self

    def task(self, name='', total=1, current=0,
             resume=False, subtask=False, **kw):
        self = self.active()
        children = self.children
        kw['parent'] = self
        kw['depth'] = self.depth + 1
        kw['outstream'] = self.outstream
        kw['fail_parent'] = self.fail_parent
        kw['active'] = self.active
        task = __class__(name=name, total=total, current=current,
                              resume=resume, subtask=subtask, **kw)
        children[id(task)] = task
        task.check_tell(None)
        return task

    def notice(self, fmt, *args):
        self = self.active()

        text = fmt % args
        lines = []
        append = lines.append

        for text_line in text.split('\n'):
            line = self.prefix_filler * (self.depth-1) + self.notice_mark
            line += text_line
            append(line)

        final_text = '\n'.join(lines)
        self.output(final_text, feed=1, eject=1)

    def __enter__(self):
        if self.disabled:
            m = "Task '%s' has been disabled" % (self.name,)
            raise ValueError(m)
        return self

    def __exit__(self, exc_type, exc_val, exc_tb):
        if exc_type is None:
            if not self.resuming:
                self.end(1)
            self.resuming = 0
            return None

        self.end(-1)
        if self.raise_errors:
            return None
        if not self.suppress_exceptions:
            import traceback
            traceback.print_exc()
        return True

    def end(self, finished, name='', tell=None):
        if self.disabled:
            return

        self.finished = finished
        eject = 2
        parent = self.parent
        if parent and parent.parent:
            eject = 1
        self.check_tell(tell, eject=eject)

        task = self
        while 1:
            if task is None or task.name.startswith(name):
                break
            task = task.parent

        if task is not None:
            parent = task.parent
            if parent is not None:
                parent.kill_child(id(task))
                if finished < 0 and task.fail_parent:
                    parent.fail(tell=tell)

        task.disable()

    def resume(self):
        self = self.active()
        self.resuming = 1
        return self

    def status(self, status_fmt, *status_args, **kw):
        self = self.active()
        tell = kw.get('tell', None)
        self.status_fmt = status_fmt
        self.status_args = status_args
        self.check_tell(tell)

    def progress(self, current, tell=None):
        self = self.active()
        self.current = current
        total = self.total
        self.status_fmt = self.default_status_fmt
        self.status_args = (current, total)
        if total and current >= total:
            self.finished = 1

        self.check_tell(tell)

    def advance(self, delta_current=1, tell=None):
        self = self.active()
        current = self.current + delta_current
        self.current = current
        total = self.total
        self.status_fmt = self.default_status_fmt
        self.status_args = (current, total)
        if total and current >= total:
            self.finished = 1

        self.check_tell(tell)

    def get_current(self):
        self = self.active()
        return self.current

    def get_total(self):
        self = self.active()
        return self.total

    def get_finished(self):
        self = self.active()
        return self.finished

    def finish(self, name='', tell=None):
        self = self.active()
        return self.end(1, name=name, tell=tell)

    def fail(self, name='', tell=None):
        self = self.active()
        return self.end(-1, name=name, tell=tell)


_teller = Teller()
