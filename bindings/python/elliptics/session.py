from elliptics.core import *
from elliptics.route import *

class Session(Session):

    @property
    def routes(self):
        return self.get_routes()

    def get_routes(self):
        return RouteList.from_routes(super(Session, self).get_routes())