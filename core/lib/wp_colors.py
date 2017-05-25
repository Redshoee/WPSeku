#!/usr/bin/env python 
# -*- coding:utf-8 -*- 
# WPSeku - Wordpress Security Scanner 
# Coded by Momo Outaadi (@M4ll0k) (C) 2017


class WPColors:
	"""Simple Color List"""
	def red(self,num):
		# red color 
		return "\033["+str(num)+";31m"

	def green(self,num):
		# green color
		return "\033["+str(num)+";32m"

	def yellow(self,num):
		# yellow color
		return "\033["+str(num)+";33m"

	def blue(self,num):
		# blue color
		return "\033["+str(num)+";34m"

	def white(self,num):
		# white color
		return "\033["+str(num)+";38m"

	def end(self):
		# reset color
		return "\033[0m"
