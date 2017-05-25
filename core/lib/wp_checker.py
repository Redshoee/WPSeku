#!/usr/bin/env python 
# -*- coding:utf-8 -*- 
# WPSeku - Wordpress Security Scanner 
# Coded by Momo Outaadi (@M4ll0k) (C) 2017

class WPChecker:
	"""Check url Class"""
	def check(self,url,path):
		if url.endswith("/") and path.startswith("/"):
			return url+path[1:]
		if url.endswith("/") and not path.startswith("/"):
			return url+path
		if not url.endswith("/") and path.startswith("/"):
			return url+path
		if not url.endswith("/") and not path.startswith("/"):
			return url+"/"+path