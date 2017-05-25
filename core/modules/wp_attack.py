 #!/usr/bin/env python 
# -*- coding:utf-8 -*- 
# WPSeku - Wordpress Security Scanner 
# Coded by Momo Outaadi (M4ll0k) (C) 2017

from core.lib import wp_checker
from core.lib import wp_colors
from core.lib import wp_print
from core.lib import wp_request
import re
import sys 
import urllib 


class WPAttack:
	"""Attack"""
	check_ = wp_checker.WPChecker()
	print_ = wp_print.WPPrint()
	#########################################################
	def __init__(self,agent,proxy,redirect,url,method,payload):
		self.url = url
		self.method = method
		self.payload = payload
		# requests
		self.req = wp_request.WPRequest(agent=agent,proxy=proxy,redir=redirect)

	def xss(self):
		# Simple testing xss vulns
		self.print_.aprint("Testing xss vulns...")
		print ""
		# self.payload ==> {'id':2,'cat':2}
		params = dict([x.split("=") for x in self.payload.split("&")])
		param = {}
		# open file core/db/wpxss.txt, mode read
		db = open("core/db/wpxss.txt","rb")
		file = [x.split("\n") for x in db]
		try:
			for item in params.items():
				for x in file:
					# 
					param[item[0]]=item[1].replace(item[1],x[0])
					# encode payload
					enparam = urllib.urlencode(param)
					# check url 
					url = self.check_.check(self.url,"")
					# return data,url,code and headers
					html,uri,code,info = self.req.Send(url,self.method,enparam)
					# search payload in html
					if re.search(x[0],html) and code == 200:
						print "%s[%s][%s][vuln]%s %s"%(wp_colors.WPColors().red(1),code,self.method,wp_colors.WPColors().end(),uri)
					else:
						print "%s[%s][%s][not vuln]%s %s"%(wp_colors.WPColors().green(1),code,self.method,wp_colors.WPColors().end(),uri)
					# return original data 
					param[item[0]] = item[1].replace(x[0],item[1])
		except Exception,err:
			pass
		sys.exit()

	def dberror(self,data):
		# MySQL error: You have an error in your SQL syntax
		if re.search('You have an error in your SQL syntax',data):
			return "MySQL Injection"
		# MySQL error: supplied argument is not a valid MySQL
		if re.search('supplied argument is not a valid MySQL',data):
			return "MySQL Injection"
		# Access-Based SQL error: Microsoft ODBC Microsoft Access Driver
		if re.search('Microsoft ODBC Microsoft Access Driver',data):
			return "Access-Based SQL Injection"
		# MSSQL-Based error: Microsoft OLE DB Provider for ODBC Drivers</font> <font size="2" face="Arial">error
		if re.search('Microsoft OLE DB Provider for ODBC Drivers</font> <font size="2" face="Arial">error',data):
			return "MSSQL-Based Injection"
		# MSSQL-Based error: Microsoft OLE DB Provider for ODBC Drivers
		if re.search('Microsoft OLE DB Provider for ODBC Drivers',data):
			return "MSSQL-Based Injection"
		# Java.SQL error: java.sql.SQLException: Syntax error or access violation
		if re.search('java.sql.SQLException: Syntax error or access violation',data):
			return "Java.SQL Injection"
		# PostgreSQL error: PostgreSQL query failed: ERROR: parser:
		if re.search('PostgreSQL query failed: ERROR: parser:',data):
			return "PostgreSQL Injection"
		# XPath error: XPathException 
		if re.search('XPathException',data):
			return "XPath Injection"
		# LDAP error: supplied argument is not a valid ldap, javax.naming.NameNotFoundException
		if re.search('supplied argument is not a valid ldap',data) or re.search('javax.naming.NameNotFoundException',data):
			return "LDAP Injection"
		# DB2 error: DB2 SQL error:
		if re.search('DB2 SQL error:',data):
			return "DB2 Injection"
		# Interbase error: Dynamic SQL Error
		if re.search('Dynamic SQL Error',data):
			return "Interbase Injection"
		# Sybase error: Sybase message:
		if re.search('Sybase message:',data):
			return "Sybase Injection"
		# Oracle error: ORA-....
		oracle = re.search('ORA-[0-9]',data)
		if oracle != None:
			return "Oracle Injection"+" "+oracle.group(0)

	def sql(self):
		# Simple testing sql vulns
		self.print_.aprint("Testing sql injection vulns...")
		print ""
		# self.payload ==> {'id':2,'cat':2}
		params = dict([x.split("=") for x in self.payload.split("&")])
		param = {}
		db = open("core/db/wpsql.txt","rb")
		# open file core/db/wpxss.txt, mode read
		file = [x.split("\n") for x in db]
		try:
			for item in params.items():
				for x in file:
					param[item[0]]=item[1].replace(item[1],x[0])
					# encode params 
					enparam = urllib.urlencode(param)
					# check url 
					url = self.check_.check(self.url,"")
					# return data,url,code and headers
					html,uri,code,info = self.req.Send(url,self.method,enparam)
					# return from db error 
					data = self.dberror(html)
					if data != None:
						print "%s[%s][%s][%s]%s %s"%(wp_colors.WPColors().red(1),code,self.method,data,wp_colors.WPColors().end(),uri)
					else:
						print "%s[%s][%s][Not vuln]%s %s"%(wp_colors.WPColors().green(1),code,self.method,wp_colors.WPColors().end(),uri)
					# return original data 
					param[item[0]] = item[1].replace(x[0],item[1])
		except Exception,err:
			pass
		sys.exit()

	def lfi(self):
		# Simple testing lfi vulns
		self.print_.aprint("Testing lfi vulns...")
		print ""
		# self.payload ==> {'id':2,'cat':2}
		params = dict([x.split("=") for x in self.payload.split("&")])
		param = {}
		db = open("core/db/wplfi.txt","rb")
		# open file core/db/wpxss.txt, mode read
		file = [x.split("\n") for x in db]
		try:
			for item in params.items():
				for x in file:
					# 
					param[item[0]]=item[1].replace(item[1],x[0])
					# encode params
					enparam = urllib.urlencode(param)
					# check url
					url = self.check_.check(self.url,"")
					# return data,url,code and headers
					html,uri,code,info = self.req.Send(url,self.method,enparam)
					if re.search("define (\W+\w+\W+\w+\W+\w)*",html) and code == 200:
						print "[%s][%s][Vuln] %s"%(wp_colors.WPColors().green(1),code,self.method,wp_colors.WPColors().end(),uri)
					else:
						print "%s[%s][%s][Not Vuln]%s %s"%(wp_colors.WPColors().green(1),code,self.method,wp_colors.WPColors().end(),uri)
					param[item[0]] = item[1].replace(x[0],item[1])
		except Exception,err:
			pass
		sys.exit()