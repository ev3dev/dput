# dput/methods/http.py
# Part of ‘dput’, a Debian package upload toolkit.
#
# This is free software, and you are welcome to redistribute it under
# certain conditions; see the end of this file for copyright
# information, grant of license, and disclaimer of warranty.

""" Implementation for HTTP upload method. """

import getpass
import http.client
import os
import sys
import urllib.request

from ..helper import dputhelper


class PromptingPasswordMgr(urllib.request.HTTPPasswordMgr):
    """ Password manager that prompts at the terminal.

        Custom HTTP password manager that prompts for a password using
        getpass() if required, and mangles the saved URL so that only
        one password is prompted for.

        """

    def __init__(self, username):
        urllib.request.HTTPPasswordMgr.__init__(self)
        self.username = username

    def find_user_password(self, realm, authuri):
        # Hack so that we only prompt for a password once
        authuri = self.reduce_uri(authuri)[0]
        authinfo = urllib.request.HTTPPasswordMgr.find_user_password(
                self, realm, authuri)
        if authinfo != (None, None):
            return authinfo

        password = getpass.getpass("    Password for %s:" % realm)
        self.add_password(realm, authuri, self.username, password)
        return (self.username, password)


class AuthHandlerHackAround:
    """ Fake request and parent object. """

    def __init__(self, url, resp_headers, pwman):
        # fake request header dict
        self.headers = {}
        # data
        self.url = url
        self.resp_headers = resp_headers
        self.authhandlers = []
        self.timeout = {}
        # digest untested
        for authhandler_class in [
                urllib.request.HTTPBasicAuthHandler,
                urllib.request.HTTPDigestAuthHandler]:
            ah = authhandler_class(pwman)
            ah.add_parent(self)
            self.authhandlers.append(ah)

    # fake request methods
    def add_header(self, k, v):
        self.headers[k] = v

    def add_unredirected_header(self, k, v):
        self.headers[k] = v

    def get_full_url(self):
        return self.url

    # fake parent method
    def open(self, *args, **keywords):
        pass

    # and what we really want
    def get_auth_headers(self):
        for ah in self.authhandlers:
            try:
                ah.http_error_401(self, None, 401, None, self.resp_headers)
            except ValueError as e:
                pass
        if self.headers:
            return self.headers
        return self.headers


def upload(
        fqdn, login, incoming, files_to_upload, debug, dummy,
        progress=0, protocol="http"):
    """ Upload the files via WebDAV. """

    # EXCEPTION HANDLING!
    if protocol == 'https':
        connclass = http.client.HTTPSConnection
    elif protocol == 'http':
        connclass = http.client.HTTPConnection
    else:
        sys.stderr.write("Wrong protocol for upload http[s].py method\n")
        sys.exit(1)
    if not incoming.startswith('/'):
        incoming = '/' + incoming
    if not incoming.endswith('/'):
        incoming += '/'
    unprocessed_files_to_upload = files_to_upload[:]
    auth_headers = {}
    pwman = PromptingPasswordMgr(login)
    while unprocessed_files_to_upload:
        afile = unprocessed_files_to_upload[0]
        path_to_package, package_name = os.path.split(afile)
        sys.stdout.write("  Uploading %s: " % package_name)
        sys.stdout.flush()
        try:
            size = os.stat(afile).st_size
        except Exception:
            sys.stderr.write("Determining size of file '%s' failed\n" % afile)
            sys.exit(1)
        f = open(afile, 'rb')
        if progress:
            f = dputhelper.FileWithProgress(
                    f, ptype=progress,
                    progressf=sys.stderr,
                    size=size)
        url_path = incoming + package_name
        url = "%s://%s%s" % (protocol, fqdn, url_path)
        if debug:
            sys.stdout.write("D: HTTP-PUT to URL: %s\n" % url)
        conn = connclass(fqdn)
        conn.putrequest("PUT", url_path, skip_accept_encoding=True)
        # Host: should be automatic
        conn.putheader('User-Agent', 'dput')
        for k, v in auth_headers.items():
            conn.putheader(k, v)
        conn.putheader('Connection', 'close')
        conn.putheader('Content-Length', str(size))
        conn.endheaders()
        pos = 0
        while pos < size:
            # sending in 64k steps (screws progress a bit)
            s = f.read(65536)
            conn.send(s)
            pos += len(s)
        f.close()
        s = ""
        res = conn.getresponse()
        if res.status >= 200 and res.status < 300:
            sys.stdout.write("done.\n")
            del unprocessed_files_to_upload[0]
        elif res.status == 401 and not auth_headers:
            sys.stdout.write("need authentication.\n")
            auth_headers = AuthHandlerHackAround(
                    url, res.msg, pwman).get_auth_headers()
        else:
            if res.status == 401:
                sys.stdout.write(
                        "Upload failed as unauthorized: %s\n"
                        "  Maybe wrong username or password?\n" % res.reason)
            else:
                sys.stdout.write(
                        "Upload failed: %d %s\n" % (res.status, res.reason))
            sys.exit(1)
        # must be done, but we're not interested
        res.read()


# Copyright © 2015–2018 Ben Finney <bignose@debian.org>
# Copyright © 2008–2012 Y Giridhar Appaji Nag <appaji@debian.org>
# Copyright © 2007–2008 Thomas Viehmann <tv@beamnet.de>
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
