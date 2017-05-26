#!/usr/bin/env python 
# -*- coding:utf-8 -*- 
# WPSeku - Wordpress Security Scanner 
# Coded by Momo Outaadi (M4ll0k) (C) 2017
#
# This program is free software: you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation, either version 3 of the License, or
# (at your option) any later version.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program.  If not, see <http://www.gnu.org/licenses/>.

import os
import sys
import time
import datetime
import getopt
import urlparse
from core.lib import wp_colors
from core.lib import wp_print
from core.lib import wp_info
from core.lib import wp_checker
from core.lib import wp_request
from core.lib import wp_banner
from core.modules import wp_generic
from core.modules import wp_theme
from core.modules import wp_users
from core.modules import wp_plugin
from core.modules import wp_attack
from core.modules import wp_brute


class WPSeku(object):
	"""WPSeku Class"""
	###########################
	print_ = wp_print.WPPrint()
	check_ = wp_checker.WPChecker()
	user_agent = ""
	proxy = None
	cookie = None
	redirect = True
	brute = None
	user = None
	sql = False
	xss = False
	lfi = False
	method = None
	wordlist = None
	query = None
	###########################
	def __init__(self,kwargs):
		self.kwargs = kwargs

	def Usage(self):
		wp_banner.Banner()
		name = os.path.join(os.path.basename(sys.argv[0]))
		print "Usage: {} [-t/--target] http://target.com\n".format(name)
		print "\t-t --target\tTarget url (eg: http://target.com)"
		print "\t-x --xss\tTesting Cross Site Scripting (xss) vulns"
		print "\t-s --sql\tTesting SQL Injection (sql) vulns"
		print "\t-l --lfi\tTesting Local File Inclusion (lfi) vulns"
		print "\t-b --brute\tBruteforcing login, wp-login [l] or xmlrpc [x]"
		print "\t-q --query\tTestable parameters (eg:\"id=1&file=2\")"
		print "\t-u --user\tSet username for bruteforce, default=admin"
		print "\t-w --wordlist\tSet wordlist (user:pass)"
		print "\t-m --method\tSet method (GET or POST)"
		print "\t-p --proxy\tSet proxy (host:port)"
		print "\t-a --agent\tSet user-agent"
		print "\t-c --cookie\tSet cookie"
		print "\t-r --redirect\tRedirection target url, defaul=True"
		print "\t-h --help\tShow this help and exit\n"		
		print "Examples:"
		print "\t{} -t http://www.target.com".format(name)
		print "\t{} -t target.com/wp-admin/admin-ajax.php -q id=1&cat=2 -m POST [-x,-s,-l]".format(name)
		print "\t{} -t target.com/path/wp-content/plugins/hello/hello.php -q id=1&test=2 -m GET [-x,-s,-l]".format(name)
		print "\t{} -t http://target.com --brute [l,x] --user admin --wordlist dict.txt\n".format(name)
		sys.exit()

	def CheckUrl(self,target):
		# Check url 
		scheme = urlparse.urlsplit(target).scheme.lower()
		netloc = urlparse.urlsplit(target).netloc.lower()
		path = urlparse.urlsplit(target).path.lower()
		if scheme not in ["http","https",""]:
			sys.exit(self.print_.bprint("Scheme %s not supported!! Check url"))
		if netloc == "":
			return "http://"+path
		if netloc != "":
			url = scheme+"://"+netloc
			return self.check_.check(url,path) 

	def Main(self):
		# WPSeku main
		if len(sys.argv) < 2:
			self.Usage()
		try:
			opts,args = getopt.getopt(self.kwargs,"t:xsl=:b:q:u:w:m:p:a:c:r:h:",["target=","xss","sql","lfi","brute=",
				"query=","user=","wordlist=","method=","proxy=","agent=","cookie=","redirect=","help","update"])
		except getopt.error,e: 
			self.Usage()
		# All opts
		for opt,arg in opts:
			if opt in ("-t","--target"):
				target = arg
				self.url = self.CheckUrl(target)
			if opt in ("-x","--xss"):
				self.xss = True
			if opt in ("-s","--sql"):
				self.sql = True 
			if opt in ("-l","--lfi"):
				self.lfi = True 
			if opt in ("-b","--brute"):
				self.brute = arg
				if self.brute not in ["l","x"]:
					sys.exit(self.print_.bprint("-b/--brute require args, l or x"))
			if opt in ("-q","--query"):
				self.query = arg 
			if opt in ("-u","--user"):
				self.user = arg 
			if opt in ("-w","--wordlist"):
				self.wordlist = arg 
			if opt in ("-m","--method"):
				self.method = arg 
			if opt in ("-p","--proxy"):
				self.proxy = arg 
			if opt in ("-a","--agent"):
				self.user_agent = arg
			if opt in ("-c","--cookie"):
				self.cookie = arg
			if opt in ("-r","--redirect"):
				self.redirect = arg 
			if opt in ("-h","--help"):
				self.Usage()

		#############################################
		wp_banner.Banner()
		self.print_.aprint("Target: %s"%(self.url))
		self.print_.aprint("Starting: %s"%(time.strftime('%d/%m/%Y %H:%M:%S')))
		print ""
		if not self.user_agent: self.user_agent = "Mozilla/5.0"
		if not self.proxy: self.proxy = None
		if not self.redirect: self.redirect = False
		if self.user == None: self.user = "admin"
		########################################
		if self.xss == True:
			if self.method == None:sys.exit('Method not exisits!')
			if self.query == None:sys.exit('Not found query!')
			wp_attack.WPAttack(self.user_agent,self.proxy,self.redirect,self.url,self.method,self.query).xss()
		####################
		if self.sql == True:
			if self.method == None:sys.exit('Method not exisits!')
			if self.query == None:sys.exit('Not found query!')
			wp_attack.WPAttack(self.user_agent,self.proxy,self.redirect,self.url,self.method,self.query).sql()
		####################
		if self.lfi == True:
			if self.method == None:sys.exit('Method not exisits!')
			if self.query == None:sys.exit('Not found query!')
			wp_attack.WPAttack(self.user_agent,self.proxy,self.redirect,self.url,self.method,self.query).lfi()
		####################
		if self.brute == "l":
			if self.wordlist == None: sys.exit('Wordlist not exisist')
			wp_brute.WPBrute(self.user_agent,self.proxy,self.redirect,self.url,self.cookie,self.wordlist,self.user).wplogin()
		#####################
		if self.brute == "x":
			if self.wordlist == None: sys.exit('Wordlist not exisist')
			wp_brute.WPBrute(self.user_agent,self.proxy,self.redirect,self.url,self.cookie,self.wordlist,self.user).xmlrpc()
		#####################
		if self.url:
			wp_generic.WPGeneric(self.user_agent,self.proxy,self.redirect,self.url).init()
			wp_theme.WPTheme(self.user_agent,self.proxy,self.redirect,self.url).init()
			wp_plugin.WPPlugin(self.user_agent,self.proxy,self.redirect,self.url).init()
			wp_users.WPUser(self.user_agent,self.proxy,self.redirect,self.url).init()
#####################################
if __name__ == "__main__":
	try:
		main = WPSeku(sys.argv[1:])
		main.Main()
	except KeyboardInterrupt:
		sys.exit("KeyboardInterrupt!!")
