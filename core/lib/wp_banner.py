#!/usr/bin/env python 
# -*- coding:utf-8 -*- 
# WPSeku - Wordpress Security Scanner 
# Coded by Momo Outaadi (@M4ll0k) (C) 2017

import wp_colors
import wp_info

def Banner():
	print wp_colors.WPColors().red(1)+r"   _    _______  _____      _           "+wp_colors.WPColors().end()   
	print wp_colors.WPColors().red(1)+r"  | |  | | ___ \/  ___|    | |          "+wp_colors.WPColors().end()
	print wp_colors.WPColors().red(1)+r"  | |  | | |_/ /\ `--.  ___| | ___   _  "+wp_colors.WPColors().end()
	print wp_colors.WPColors().red(1)+r"  | |/\| |  __/  `--. \/ _ \ |/ / | | | "+wp_colors.WPColors().end()
	print wp_colors.WPColors().red(1)+r"  \  /\  / |    /\__/ /  __/   <| |_| | "+wp_colors.WPColors().end()
	print wp_colors.WPColors().red(1)+r"   \/  \/\_|    \____/ \___|_|\_\\__,_| "+wp_colors.WPColors().end()
	print wp_colors.WPColors().white(0)+"                                       "+wp_colors.WPColors().end()
	print wp_colors.WPColors().yellow(1)+"||{} {}{}".format(wp_colors.WPColors().end(),wp_info.WPInfo().name(),wp_colors.WPColors().end())
	print wp_colors.WPColors().yellow(1)+"||{} {}{}".format(wp_colors.WPColors().end(),wp_info.WPInfo().version(),wp_colors.WPColors().end())
	print wp_colors.WPColors().yellow(1)+"||{} {}{}".format(wp_colors.WPColors().end(),wp_info.WPInfo().author(),wp_colors.WPColors().end())
	print wp_colors.WPColors().yellow(1)+"||{} {}{}".format(wp_colors.WPColors().end(),wp_info.WPInfo().repo(),wp_colors.WPColors().end())
	print ""
