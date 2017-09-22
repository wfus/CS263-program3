#!/usr/bin/env python2

# Do NOT change this file!

import SocketServer
import sys
import os
from telnetsrvThreaded import TelnetHandler, command


class Project3Handler(TelnetHandler):
    WELCOME = "Welcome to the Project 3 telnet server!"
    PROMPT  = "proj3 server> "

    @command(["echo"])
    def command_echo(self, params):
        '''<text to echo>
        Echo text back to the console.
        This command simply echos the provided text
        back to the console.
        '''
        self.writeresponse("".join(params))

    @command(["boom"])
    def command_boom(self, params):
        '''
        Blow up the telnet server.
        This command will cause the telnet server to
        terminate. A reasonable user would never call
        this command.
        '''
        sys.stdout.write('BOOM!\n')
        sys.stdout.flush()
        os._exit(-1)


class TelnetServer(SocketServer.TCPServer):
    allow_reuse_address = True


def main():
    if len(sys.argv) != 2:
        print "USAGE: %s port" % sys.argv[0]
        sys.exit(-1)
    server = TelnetServer(("", int(sys.argv[1])), Project3Handler)
    server.serve_forever()


if __name__ == "__main__":
    main()
