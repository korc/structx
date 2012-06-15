#!/usr/bin/python

from setuptools import setup

setup(
      name="StructX",
      author=u"Lauri Korts-P\xe4rn",
      version="1.0",
      author_email="lauri@korc.jp",
      url="http://github.com/korc/structx",
      license="GPL",
      description="Unknown binary data dissection/analyze/reassembly library",
      classifiers=[
        "Development Status :: 5 - Production/Stable",
        "License :: OSI Approved :: GNU General Public License (GPL)",
        "Environment :: Plugins",
        "Operating System :: OS Independent",
        "Programming Language :: Python",
        "Intended Audience :: Developers",
        "Intended Audience :: Information Technology",
        "Topic :: Scientific/Engineering :: Information Analysis",
        "Topic :: Software Development :: Disassemblers",
        "Topic :: Software Development :: Libraries :: Python Modules",
    ],
      packages=["structx"],
)