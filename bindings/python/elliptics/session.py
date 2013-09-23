from elliptics.core import Session
from elliptics.route import RouteList

class Session(Session):

    @property
    def routes(self):
        return self.get_routes()

    def get_routes(self):
        return RouteList.from_routes(super(Session, self).get_routes())