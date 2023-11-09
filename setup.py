#!/usr/bin/env python
# -*- coding: utf-8 -*-

import sys

from setuptools import setup

setup(
    name='aztarna',
    version='1.2.3',
    packages=[
                'aztarna',
                'aztarna.utils',
                'aztarna.ros',
                'aztarna.ros.ros',
                'aztarna.ros.sros',
                'aztarna.ros.industrial',
                'aztarna.ros.ros2',
                'aztarna.industrialrouters',
              ],
    url='https://www.aliasrobotics.com/research/aztarna.htm',
    project_urls={
        'Source Code': 'https://github.com/aliasrobotics/aztarna'
    },
    license='GPLv3',
    author='Alias Robotics',
    author_email='contact@aliasrobotics.com',
    description='A footprinting tool for ROS and SROS systems',
    long_description='''Aztarna, a footprinting tool for robots. 
    Provides researchers a way for researching internet connected ROS, SROS robots, as well as industrial routers.
    
    Alias Robotics supports original robot manufacturers assessing their security and improving their quality of software.
    By no means we encourage or promote the unauthorized tampering with running robotic systems.
    This can cause serious human harm and material damages.
    ''',
    keywords=['network', 'footprinting', 'ros', 'sros', 'ics', 'industrialrouters'],
    entry_points = {
        'console_scripts': ['aztarna=aztarna.cmd:main'],
    },
    install_requires=[
        'MarkupSafe==1.1.1',
        'Pygments==2.3.1',
        'Sphinx==2.0.1',
        'XlsxWriter==1.1.6',
        'aiohttp-xmlrpc==1.5.0',
        'aiohttp==3.8.6',
        'aionmap==0.0.2',
        'aiosignal==1.3.1',
        'argcomplete==3.1.4',
        'async-timeout==4.0.3',
        'attrs==23.1.0',
        'certifi==2023.7.22',
        'chardet==5.2.0',
        'charset-normalizer==3.3.2',
        'colorama==0.4.6',
        'dnspython==2.0.0',
        'frozenlist==1.4.0',
        'idna==3.4',
        'ipwhois==1.2.0',
        'lxml==4.9.3',
        'multidict==4.5.2',
        'packaging==19.0',
        'property==2.2',
        'pycparser==2.19',
        'pyparsing==2.4.0',
        'pyshark==0.4.2.9',
        'python-libnmap==0.7.3',
        'pytz==2019.1',
        'requests==2.31.0',
        'scapy==2.4.2',
        'shodan==1.12.1',
        'six==1.12.0',
        'snowballstemmer==1.2.1',
        'sphinxcontrib-applehelp==1.0.1',
        'sphinxcontrib-devhelp==1.0.1',
        'sphinxcontrib-htmlhelp==1.0.2',
        'sphinxcontrib-jsmath==1.0.1',
        'sphinxcontrib-qthelp==1.0.2',
        'sphinxcontrib-serializinghtml==1.1.3',
        'sphinxcontrib-websupport==1.1.0',
        'urllib3==2.0.7',
        'uvloop==0.19.0',
        'yarl==1.3.0',
    ],
    include_package_data=True
)
