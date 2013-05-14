from pprint import pformat

__doc__ = \
    """
    Recovery context is just a configuration of recovery process
    """

class Ctx(object):
    __doc__ = \
        """
        Tiny wrapper for dict with better interface:
        Now you can use ctx.test = 'test', instead of ctx['test'] = 'test'
        """
    def __init__(self, **kwargs):
        self.__dict__.update(kwargs)

    def __repr__(self):
        return pformat(self.__dict__, indent=4)
