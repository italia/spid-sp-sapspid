import response

class denied(response.RequestHandler):

    def write_error(self, status_code, **kwargs):
        super(denied, self).write_error(status_code, errorcode = '3', **kwargs)

    def get(self):
        self.set_header('Content-Type', 'application/json; charset=UTF-8')
        getResponse = response.ResponseObj(httpcode=403)
        getResponse.setError('2')
        self.set_status(getResponse.error.httpcode)
        self.write(getResponse.jsonWrite())
        self.finish()

    def post(self, *args, **kwargs):
        self.get()

    def put(self):
        self.get()

    def patch(self, *args, **kwargs):
        self.get()

    def delete(self, *args, **kwargs):
        self.get()

    def head(self, *args, **kwargs):
        self.get()

    def options(self, *args, **kwargs):
        self.get()