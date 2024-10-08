# Impacket - Collection of Python classes for working with network protocols.
#
# Copyright (C) 2023 Fortra. All rights reserved.
#
# This software is provided under a slightly modified version
# of the Apache Software License. See the accompanying LICENSE file
# for more information.
#
# Description:
#   This logger is intended to be used by impacket instead
#   of printing directly. This will allow other libraries to use their
#   custom logging implementation.
#

import logging
import sys
from colorama import Fore, Back, Style

# This module can be used by scripts using the Impacket library 
# in order to configure the root logger to output events 
# generated by the library with a predefined format

# If the scripts want to generate log entries, they can write
# directly to the root logger (logging.info, debug, etc).

class ImpacketFormatter(logging.Formatter):
  '''
  Prefixing logged messages through the custom attribute 'bullet'.
  '''
  def __init__(self,color=False):
      self.color = color
      logging.Formatter.__init__(self,'%(color)s%(bullet)s%(reset_color)s %(message)s', None)

  def _add_color_inline(self, color, data):
    if self.color:
      return f'{color}{data}{Style.RESET_ALL}'
    else:
      return data

  def _add_color(self, color, record):
    if self.color:
      record.color = color
      record.reset_color = Style.RESET_ALL
    return record


  def format(self, record):
    record.color = ''
    record.reset_color = ''

    if record.levelno == logging.INFO:
      #record.bullet = self._add_color_inline(Fore.CYAN, '[*]')
      self._add_color(Fore.GREEN, record)
      record.bullet = '[+]'

    elif record.levelno == logging.DEBUG:
      #record.bullet = self._add_color_inline(Fore.GREEN, '[+]')
      self._add_color(Fore.CYAN, record)
      record.bullet = '[*]'

    elif record.levelno == logging.WARNING:
      #record.bullet = self._add_color_inline(Fore.YELLOW, '[!]')
      self._add_color(Fore.YELLOW, record)
      record.bullet = '[!]'

    else:
      #record.bullet = self._add_color_inline(Fore.RED, '[-]')
      self._add_color(Fore.RED, record)
      record.bullet = '[-]'

    return logging.Formatter.format(self, record)

class ImpacketFormatterTimeStamp(ImpacketFormatter):
  '''
  Prefixing logged messages through the custom attribute 'bullet'.
  '''
  def __init__(self, color=False):
      self.color = color

      msg_format = self._add_color_inline(Fore.LIGHTBLACK_EX, '[%(asctime)-15s]')
      msg_format += '%(color)s%(bullet)s%(reset_color)s %(message)s'
      logging.Formatter.__init__(self,msg_format, None)

  def formatTime(self, record, datefmt=None):
      return ImpacketFormatter.formatTime(self, record, datefmt="%Y-%m-%d %H:%M:%S")

def init(ts=False,color=False):
    # We add a StreamHandler and formatter to the root logger
    handler = logging.StreamHandler(sys.stdout)
    if not ts:
        handler.setFormatter(ImpacketFormatter(color=color))
    else:
        handler.setFormatter(ImpacketFormatterTimeStamp(color=color))
    logging.getLogger("SeamlessPass").addHandler(handler)
    logging.getLogger("SeamlessPass").setLevel(logging.INFO)
    logging.getLogger("SeamlessPass").propagate = False


logger = logging.getLogger("SeamlessPass")
