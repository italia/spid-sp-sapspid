import response
import asyncio

class GetVersion(response.RequestHandler):

    def write_error(self, status_code, **kwargs):
        super(self.__class__, self).write_error(status_code, errorcode = '3', **kwargs)

    async def get(self):
        self.set_header('Content-Type', 'application/json; charset=UTF-8')
        self.set_status(200)
        res = await asyncio.get_event_loop().run_in_executor(None, self.background_task)
        self.write(res)
        self.finish()

    def background_task(self):
        getResponse = response.ResponseObj(httpcode=200)
        getResponse.setError('0')
        getResponse.setResult(ApiVersion = getResponse.apiVersion)
        return getResponse.jsonWrite()

