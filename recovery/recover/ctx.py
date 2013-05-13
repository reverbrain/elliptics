from pprint import pformat

__doc__ = \
"""
Recovery context - configuration of recovery process
"""

class Ctx(object):
    __doc__ = """XXX:"""

    def __init__(self, **kwargs):
        self.__dict__.update(kwargs)

    def __repr__(self):
        return pformat(self.__dict__, indent=4)
