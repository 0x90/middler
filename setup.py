import sys
import os
from distutils.core import setup, Extension

packages = ['middlerlib','middlerlib.plugins','middler.plugins.support']
mods = []
pkgdata = {}

setup  (name        = 'middler',
        version     = '1.0',
        description = 'Man-In-The-Middler tool',
        author = 'Jay Beale',
        author_email = 'jay@inguardians.com',
        packages  = packages,
        package_data = pkgdata,
        ext_modules = mods,
        scripts = ['middler.py'],
       )
