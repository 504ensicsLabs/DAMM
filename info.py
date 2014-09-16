'''
    The following is located here instead of __init__ because
    pyinstaller will not happily import the project's __init__
'''
name = 'DAMM'
_major = '1'
_minor = '0'
_revision = filter(str.isdigit, '$Revision: 16 $')
_qualifier = 'alpha'
__version__ = '{major}.{minor}.{revision}{qualifier}'.format(major=_major, minor=_minor, revision=_revision, qualifier=_qualifier)
