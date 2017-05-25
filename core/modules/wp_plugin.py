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

class WPPlugin:
	"""Plugin"""
	check_ = wp_checker.WPChecker()
	print_ = wp_print.WPPrint()
	def __init__(self,agent,proxy,redirect,url):
		self.url = url
		# request
		self.req = wp_request.WPRequest(agent=agent,proxy=proxy,redir=redirect)

	def init(self):
		# Detect all current plugins
		print ""
		self.print_.aprint("Enumerating plugins...")
		try:
			# check url 
			url = self.check_.check(self.url,"")
			# return html,url,code and inf
			html,uri,code,info = self.req.Send(url)
			plugin = re.findall("/wp-content/plugins/(.+?)/",html)
			nplugin = []
			for x in plugin:
				if x not in nplugin:
					nplugin.append(x)
			if nplugin != []:
				for c in range(len(nplugin)):
					self.print_.dprint("Name: %s - %s"%(nplugin[c],self.vers(nplugin[c])))
					self.readme(nplugin[c])
					self.changelog(nplugin[c])
					self.dirlisting(nplugin[c])
					self.plvulns(nplugin[c])
			else:
				self.print_.eprint("Not found plugins!")
		except Exception,e:
			pass

	def vers(self,plugin):
		# check vers 
		try:
			url = self.check_.check(self.url,"")
			# return html,url,code and inf
			html,uri,code,info = self.req.Send(url)
			# find plugin version 
			vers = re.findall("/wp-content/plugins/%s\S+?ver=(\d+.\d+[.\d+]*)"%(str(plugin)),html)
			new = []
			for x in vers:
				if x not in new:
					new.append(x)
			if new != []:
				return new[0]
			else:
				return None
		except Exception,e:
			pass

	def readme(self,plugin):
		# check readme 
		file = ["readme.txt","readme.md","README.md","README.txt"]
		for x in file:
			try:
				url = self.check_.check(self.url,"/wp-content/plugins/"+str(plugin)+str(x))
				# return html,url,code and inf
				html,uri,code,info = self.req.Send(url)
				if html and code == 200:
					self.print_.dprint("Readme: %s"%(uri))
			except Exception,e:
				pass

	def changelog(self,plugin):
		# check changelog 
		file = ["CHANGELOG","CHANGELOG.txt","CHANGELOG.md","changelog.txt","changelog.md"]
		for x in file:
			try:
				url = self.check_.check(self.url,"/wp-content/plugins/"+str(plugin)+str(x))
				# return html,url,code and inf
				html,uri,code,info = self.req.Send(url)
				if html and code==200:
					self.print_.dprint("Changelog: %s"%(uri))
			except Exception,e:
				pass

	def dirlisting(self,plugin):
		# check common dir listing enabled
		file = ["","/js","/css","/images","/inc","/lang","/models","/markup","/admin","/src","/widgets",
		"/lib","/templates","/assets","/includes","/logs","/vendor"]
		for x in file:
			try:
				url = self.check_.check(self.url,"/wp-content/plugins/"+str(plugin)+str(x))
				# return html,url,code and inf
				html,uri,code,info = self.req.Send(url)
				if re.search("Index of",html) and code==200:
					self.print_.eprint("Listing: %s"%(uri))
			except Exception,e:
				pass

	def plvulns(self,plugin):
		# check plugin vulns
		try:
			req = requests.packages.urllib3.disable_warnings()
			req = requests.get("https://wpvulndb.com/api/v2/plugins/"+str(plugin),verify=False)
			jso = json.loads(req.content)
			if jso[str(plugin)]:
				if jso[str(plugin)]["vulnerabilities"]:
					for x in range(len(jso[str(plugin)]["vulnerabilities"])):
						print ""
						self.print_.eprint("Title: %s"%(jso[str(plugin)]["vulnerabilities"][x]["title"]))
						if jso[str(plugin)]["vulnerabilities"][x]["references"]["url"]:
							for z in range(len(jso[str(plugin)]["vulnerabilities"][x]["references"]["url"])):
								self.print_.dprint("Referce: %s"%(jso[str(plugin)]["vulnerabilities"][x]["references"]["url"][z]))
						self.print_.dprint("Fixed in: %s"%(jso[str(plugin)]["vulnerabilities"][x]["fixed_in"]))
						print ""
				else:
					self.print_.eprint("Not found vulnerabilities")
					print ""
			else:
				self.print_.eprint("Not found vulnerabilities")
				print ""
		except Exception,e:
			pass