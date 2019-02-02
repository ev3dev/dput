# dput/methods/rsync.py
# Part of ‘dput’, a Debian package upload toolkit.
#
# This is free software, and you are welcome to redistribute it under
# certain conditions; see the end of this file for copyright
# information, grant of license, and disclaimer of warranty.

""" Implementation for RSync upload method. """

import os
import sys

from ..helper import dputhelper


def upload(fqdn, login, incoming, files_to_upload, debug, dummy, progress=0):
    """ Upload the files with rsync via ssh. """

    files_to_fix = []

    for file in files_to_upload:
        to_fix = os.path.basename(file)
        file_to_fix = os.path.join(incoming, to_fix)
        files_to_fix.append(file_to_fix)

    if login and login != '*':
        login_spec = '%s@' % login
    else:
        login_spec = ''
    upload_command = [
            'rsync', '', '--copy-links', '--progress', '--partial',
            '-zave', 'ssh -x', '%s%s:%s' % (login_spec, fqdn, incoming)]
    fix_command = [
            'ssh', '%s%s' % (login_spec, fqdn), 'chmod', '0644'
            ] + files_to_fix
    upload_command[1:2] = files_to_upload

    if debug:
        sys.stdout.write(
                "D: Uploading with rsync to %s%s:%s\n"
                % (login_spec, fqdn, incoming))
    if dputhelper.check_call(upload_command) != dputhelper.EXIT_STATUS_SUCCESS:
        sys.stdout.write(
                "\n"
                "Error while uploading.\n")
        sys.exit(1)
    if debug:
        sys.stdout.write(
                "D: Fixing file permissions with %s%s\n"
                % (login_spec, fqdn))
    if dputhelper.check_call(fix_command) != dputhelper.EXIT_STATUS_SUCCESS:
        sys.stdout.write("Error while fixing permission.\n")
        sys.exit(1)


# Copyright © 2015–2018 Ben Finney <bignose@debian.org>
# Copyright © 2009 Y Giridhar Appaji Nag <appaji@debian.org>
# Copyright © 2007 Thomas Viehmann <tv@beamnet.de>
#
# This is free software: you may copy, modify, and/or distribute this work
# under the terms of the GNU General Public License as published by the
# Free Software Foundation; version 3 of that license or any later version.
# No warranty expressed or implied. See the file ‘LICENSE.GPL-3’ for details.


# Local variables:
# coding: utf-8
# mode: python
# End:
# vim: fileencoding=utf-8 filetype=python :
