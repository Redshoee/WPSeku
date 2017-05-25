#!/usr/bin/env python 
# -*- coding:utf-8 -*- 
# WPSeku - Wordpress Security Scanner 
# Coded by Momo Outaadi (@M4ll0k) (C) 2017

from core.lib import wp_checker
from core.lib import wp_colors
from core.lib import wp_print
from core.lib import wp_request
import re
import requests 
import json

class WPTheme:
	"""Theme"""
	check_ = wp_checker.WPChecker()
	print_ = wp_print.WPPrint()
	def __init__(self,agent,proxy,redirect,url):
		self.url = url
		# request 
		self.req = wp_request.WPRequest(agent=agent,proxy=proxy,redir=redirect)

	def init(self):
		# Detect current theme
		print ""
		self.print_.aprint("Enumerating themes... ")
		try:
			# check url
			url = self.check_.check(self.url,"")
			# return html,url,code and info
			html,uri,code,info = self.req.Send(url)
			# find theme
			theme = re.findall("/wp-content/themes/(.+?)/",html)
			new = []
			for z in theme:
				if z not in new:
					new.append(z)
			if new != []:
				for x in range(len(new)):
					self.print_.dprint("Name: %s"%(new[x]))
					self.info(new[x])
					self.readme(new[x])
					self.changelog(new[x])
					self.fullpathdisc(new[x])
					self.style(new[x])
					self.thvulns(new[x])
			else:
				self.print_.eprint("Not found themes!")
		except Exception,e:
			pass 

	def info(self,theme):
		# check info 
		try:
			# check url 
			url = self.check_.check(self.url,"/wp-content/themes/%s%s"%(theme,"/style.css"))
			# return html,url,code and info
			html,uri,code,info = self.req.Send(url)
			if html and code == 200:
				self.print_.dprint("Theme Name: %s"%(re.findall("Theme Name: (\w+)",html)[0]))
				self.print_.dprint("Theme URI: %s"%(re.findall("Theme URI: (\S+)",html)[0]))
				self.print_.dprint("Author: %s"%(re.findall("Author: (\S+)",html)[0]))
				self.print_.dprint("Author URI: %s"%(re.findall("Author URI: (\S+)",html)[0]))
				self.print_.dprint("Version: %s"%(re.findall("Version: (\d+.\d+[.\d+]*)",html)[0]))
		except Exception,e:
			pass

	def readme(self,theme):
		# check readme file 
		file = ["/readme.txt","/README.txt","/readme.md","/README.md"]
		for x in file:
			try:
				# check url 
				url = self.check_.check(self.url,"/wp-content/themes/%s%s"%(theme,x))
				# return html,url,code and info 
				html,uri,code,info = self.req.Send(url)
				if html and code == 200:
					self.print_.dprint("Readme: %s"%(uri))
			except Exception,e:
				pass 

	def changelog(self,theme):
		# check changelog file
		file = ["/CHANGELOG","/changelog.txt","/changelog.md","/CHANGELOG.md","/CHANGELOG.txt"]
		for x in file:
			try:
				# check url
				url = self.check_.check(self.url,"/wp-content/themes/%s%s"%(theme,x))
				# return html,url,code and info 
				html,uri,code,info = self.req.Send(url)
				if html and code == 200:
					self.print_.dprint("Changelog: %s"%(uri))
			except Exception,e:
				pass

	def fullpathdisc(self,theme):
		# check fpd
		file = ["/404.php","/archive.php","/author.php","/comments.php","/footer.php","/functions.php",
		"/header.php","/image.php","/page.php","/search.php","/single.php","/archive.php"]
		for x in file:
			try:
				# check url 
				url = self.check_.check(self.url,"/wp-content/themes/%s%s"%(theme,x))
				# return html,url,code and info 
				html,uri,code,info = self.req.Send(url)
				if html and code==200:
					if re.search("Faral error",html):
						self.print_.eprint("Full Path Disclosure: %s"%(uri))
			except Exception,e:
				pass

	def style(self,theme):
		# check theme style for more info 
		try:
			# check url
			url = self.check_.check(self.url,"/wp-content/themes/%s%s"%(theme,"/style.css"))
			# return html,url,code and info 
			html,uri,code,info = self.req.Send(url)
			if html and code == 200:
				self.print_.dprint("Style: %s"%(uri))
		except Exception,e:
			pass

	def thvulns(self,theme):
		# check theme vulns
		try:
			req = requests.packages.urllib3.disable_warnings()
			req = requests.get("https://www.wpvulndb.com/api/v2/themes/"+str(theme),verify=False)
			jso = json.loads(req.content)
			if jso[str(theme)]:
				if jso[str(theme)]["vulnerabilities"]:
					for x in range(len(jso[str(theme)]["vulnerabilities"])):
						self.print_.eprint("Title: %s"%(jso[str(theme)]["vulnerabilities"][x]["title"]))
						if jso[str(theme)]["vulnerabilities"][x]["references"]["url"]:
							for z in range(len(jso[str(theme)]["vulnerabilities"][x]["references"]["url"])):
								self.print_.dprint("Referce: %s"%(jso[str(theme)]["vulnerabilities"][x]["references"]["url"][z]))
						self.print_.dprint("Fixed in: %s"%(jso[str(theme)]["vulnerabilities"][x]["fixed_in"]))
						print ""
				else:
					self.print_.eprint("Not found vulnerabilities")
			else:
				self.print_.eprint("Not found vulnerabilities")
		except Exception,e:
			pass

