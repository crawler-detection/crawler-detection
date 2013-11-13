from setuptools import setup, find_packages

setup(name='crawler_detection',
      version='0.1',
      author='Your Name',
      author_email='your@email',
      license='MIT',
      #packages=['crawler_detection'],
      install_requires=['pandas ==0.12.0','apachelog ==1.0','numpy ==1.8.0','httpbl','BulkWhois ==0.2.1'],
      description='Example package that says hello',
      py_modules=['crawler_detection'])
