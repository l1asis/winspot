import logging
from importlib.metadata import PackageNotFoundError, version

__name__ = "winspot"

try:
    __version__ = version("winspot")
except PackageNotFoundError:
    __version__ = "unknown"

__about__ = rf"""
         .________________________.
         |&**   _@*@     @@**@    |
         |*&   / \@*@ ,   @@*  ,  |
         |    /   \         ,     |
         |*\ /_____\ ,   ,     ,  |
         |#| |  _  |       ,      |
         |#| |_|_|_|___.-~.-~.-~._|
        /________________________/
         
   Don't let them take your skyscapes away.
                Save them with winspot now.

  winspot: The missing CLI for Windows Spotlight management.
  ----------------------------------------------------------
  Version:      {__version__}
  Author:       Volodymyr Horshenin (@l1asis)
  License:      MIT
  Repository:   https://github.com/l1asis/winspot

  Description: 
  A utility to export and reset Windows Spotlight images 
  from hidden system caches.

  Made with respect for the Windows community.
"""

logger = logging.getLogger(__name__)
logger.addHandler(logging.NullHandler())
