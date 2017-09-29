import response


class StaticFileHandler(response.StaticFileHandler):

    def write_error(self, status_code, **kwargs):
        super(StaticFileHandler, self).write_error(status_code, errorcode = '3', **kwargs)