#!/usr/bin/env python 
# -*- coding:utf-8 -*- 
# WPSeku - Wordpress Security Scanner 
# Coded by Momo Outaadi (@M4ll0k) (C) 2017

from core.lib import wp_checker
from core.lib import wp_colors
from core.lib import wp_print
from core.lib import wp_request
import re
import json

class WPUser:
	"""Wordpress Enumeration Users"""
	check_ = wp_checker.WPChecker()
	print_ = wp_print.WPPrint()
	def __init__(self,agent,proxy,redirect,url):
		self.url = url 
		self.req = wp_request.WPRequest(agent=agent,proxy=proxy,redir=redirect)
		self.users = []

	def wpjson(self):
		# Enumeration users via wp-json
		# https://www.exploit-db.com/exploits/41497/
		try:
			url = self.check_.check(self.url,"/wp-json/wp/v2/users")
			html,uri,code,info = self.req.Send(url)
			# return html,url,code and info 
			if html and code == 200:
				user = json.loads(html,"utf-8")
				for x in range(len(user)):
					self.users.append(user[x]["name"])
		except Exception,e:
			pass

	def wpauthor(self):
		# Enumeration users via /?author=
		for x in range(0,15):
			try:
				url = self.check_.check(self.url,"/?author="+str(x))
				# return html,url,code and info 
				html,uri,code,info = self.req.Send(url)
				# find usernames with this regex
				user = re.findall('author author-(.+?) ',html)
				user_= re.findall('/author/(.+?)/feed/',html)
				if user:
					self.users.extend(user)
				if user_:
					self.users.extend(user_)
			except Exception,e:
				pass

	def wpfeed(self):
		# Enumeration users via /?feed=rss2
		try:
			url = self.check_.check(self.url,"/?feed=rss2")
			# return html,url,code and info 
			html,uri,code,info = self.req.Send(url)
			# find usernames with this regex
			user = re.findall('<dc:creator><!\[CDATA\[(.+?)\]\]></dc:creator>',html)
			if user:
				self.users.extend(user)
		except Exception,e:
			pass

	def init(self):
		print ""
		self.print_.aprint("Enumerating usernames...")
		self.wpjson()
		self.wpauthor()
		self.wpfeed()
		users = []
		for x in self.users:
			if x not in users:
				users.append(x)
		if users != []:
			for z in range(len(users)):
				self.print_.dprint(u"ID: {} - Name: {}".format(z,users[z]))
			print ""
		elif users == []:
			self.print_.eprint("Not found users ")

