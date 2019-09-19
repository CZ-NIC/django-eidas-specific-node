"""Setup script for eidas_node."""
from setuptools import find_packages, setup

import eidas_node


setup(name='eidas_node',
      version=eidas_node.__version__,
      author='Jiří Janoušek',
      author_email='jiri.janousek@nic.cz',
      url='https://github.com/CZ-NIC/django-eidas-specific-node',
      description='An implementation of eIDAS-Node 2.3.x Specific Connector and Proxy Service.',
      long_description=open('README.md', encoding='utf-8').read(),
      long_description_content_type='text/markdown',
      classifiers=[
            'License :: OSI Approved :: GNU General Public License v3 or later (GPLv3+)',
      ],
      python_requires='~=3.5',
      packages=find_packages(),
      include_package_data=True,
      install_requires=open('requirements.txt').read().splitlines(),
      extras_require={'ignite': 'pyignite',
                      'quality': ['isort', 'flake8', 'pydocstyle', 'mypy'],
                      'tests': ['freezegun']})
