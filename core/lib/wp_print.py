#!/usr/bin/env python 
# -*- coding:utf-8 -*- 
# WPSeku - Wordpress Security Scanner 
# Coded by Momo Outaadi (@M4ll0k) (C) 2017

import wp_colors

class WPPrint:
	"""Simple Class Printer"""
	r = wp_colors.WPColors().red(1) #red
	nr = wp_colors.WPColors().red(0) # normal red
	y = wp_colors.WPColors().yellow(1) # yellow
	ny = wp_colors.WPColors().yellow(0) # normal yellow 
	w = wp_colors.WPColors().white(1) # white
	nw = wp_colors.WPColors().white(0) # normal white
	e = wp_colors.WPColors().end() # reset 
	g = wp_colors.WPColors().green(1) # green
	ng = wp_colors.WPColors().green(0) # normal green

 	def aprint(self,string,flag="##"):
		# flag = green 
		print u"{}{}{} {}{}{}".format(self.g,flag,self.e,self.nw,string,self.e)

	def bprint(self,string,flag="##"):
		# flag = red
		print u"{}{}{} {}{}{}".format(self.r,flag,self.e,self.nw,string,self.e)

	def cprint(self,string,flag="##"):
		# flag = yellow
		print u"{}{}{} {}{}{}".format(self.y,flag,self.e,self.nw,string,self.e)

	def dprint(self,string,flag="||"):
		# flag = green
		print u"\t{}{}{} {}{}{}".format(self.g,flag,self.e,self.nw,string,self.e)

	def eprint(self,string,flag="||"):
		# flag = red
		print u"\t{}{}{} {}{}{}".format(self.r,flag,self.e,self.nw,string,self.e)

