# Copyright (c) 2009 Moxie Marlinspike
#
# This program is free software; you can redistribute it and/or
# modify it under the terms of the GNU General Public License as
# published by the Free Software Foundation; either version 3 of the
# License, or (at your option) any later version.
#
# This program is distributed in the hope that it will be useful, but
# WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
# General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program; if not, write to the Free Software
# Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA 02111-1307
# USA
#

import syslog
import subprocess
import time, os, sys

from struct import *
from knockknock.Profile import Profile
from LogEntry import LogEntry
from MacFailedException import MacFailedException

class KnockWatcher:

    def __init__(self, config, logFile, profiles, portOpener):
        self.config     = config
        self.logFile    = logFile
        self.profiles   = profiles
        self.portOpener = portOpener

    def getProfile(self, sourceIP):
    	homedir = os.path.expanduser('~')
	if not os.path.isdir(homedir + '/.knockknock/'):
            syslog.syslog("Error: you need to setup your profiles in " + homedir + '/.knockknock/')
            sys.exit(2)

    	if not os.path.isdir(homedir + '/.knockknock/' + sourceIP):
            syslog.syslog("Error: profile for host " + sourceIP + " not found at " + homedir + "/.knockknock/" + sourceIP)
            sys.exit(2)

        return Profile(homedir + '/.knockknock/' + sourceIP)
			

    def existsInPath(self, command):
    	def isExe(fpath):
            return os.path.exists(fpath) and os.access(fpath, os.X_OK)

	for path in os.environ["PATH"].split(os.pathsep):
            exeFile = os.path.join(path, command)
            if isExe(exeFile):
            	return exeFile
	return None

    def tailAndProcess(self):
        for line in self.logFile.tail():
            try:
                logEntry = LogEntry(line)
                profile  = self.profiles.getProfileForPort(logEntry.getDestinationPort())

                if (profile != None):
                    try:
                        ciphertext = logEntry.getEncryptedData()
                        port       = profile.decrypt(ciphertext, self.config.getWindow())
                        sourceIP   = logEntry.getSourceIP()
                    
                        self.portOpener.open(sourceIP, port)
                        syslog.syslog("Received authenticated port-knock for port " + str(port) + " from " + sourceIP)
			#knock-ack		
			profile      = self.getProfile(sourceIP)
			syslog.syslog("Profile obtained for" + sourceIP)
    			packetData   = profile.encrypt(port)
			syslog.syslog("Payload for knock-ack prepared")
    			knockPort    = profile.getKnockPort()

			(idField, seqField, ackField, winField) = unpack('!HIIH', packetData)
			hping = existsInPath("hping3")

   			if hping is None:
        		    syslog.syslog("Error, you must install hping3 first.")
        		    sys.exit(2)	

			command = [hping, "-S", "-c", "1",
               			   "-p", str(knockPort),
               			   "-N", str(idField),
               			   "-w", str(winField),
               			   "-M", str(seqField),
               			   "-L", str(ackField),
               			   host]
			try:
        		    subprocess.call(command, shell=False, stdout=open('/dev/null', 'w'), stderr=subprocess.STDOUT)
			    syslog.syslog("Knock-ack sent for port " + str(port) + " to " + sourceIP)
        		    #print "Knock-ack sent."
# knock-ack end
    			except OSError:
        		    syslog.syslog("Error: Do you have hping3 installed?")
        		    sys.exit(3)			
			
                    except MacFailedException:
                        pass
            except Exception as e:
#                print "Unexpected error:", sys.exc_info()
                syslog.syslog("knocknock skipping unrecognized line" + str(e))
