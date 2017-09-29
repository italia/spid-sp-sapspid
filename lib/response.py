#import jsonlib2
import globalsObj
import logging
import traceback
import tornado.web
#import ujson
#import simplejson
import jsonpickle
import uuid


class Result(object):
    def __init__(self, **kwargs):
        #self.rootLogger = logging.getLogger('root')
        for name, value in kwargs.items():
            exec("self." + name + " = value")

    def reload(self,**kwargs):
        self.__init__(**kwargs)

class Error(object):
    def __init__(self, **kwargs):
        #self.rootLogger = logging.getLogger('root')
        for name, value in kwargs.items():
            exec("self." + name + " = value")

    def setSection(self,section):
        if globalsObj.errors_configuration.has_section(section):
            errorsDict = dict(globalsObj.errors_configuration.items(section))
            for key, val in enumerate(errorsDict.keys()):
                exec("self." + val + " = errorsDict[val]")
            #if self.code is not None:
            #    self.code = int(self.code)
            return True
        else:
            logging.getLogger(__name__).error("Error section %s not present" % (section))
            return False

    def reload(self,**kwargs):
        self.__init__(**kwargs)


class ResponseObj(object):
    def __init__(self, ID = None, **kwargs):
        #self.rootLogger = logging.getLogger('root')
        self.apiVersion = globalsObj.configuration.get('version','version')
        self.error = None
        self.result = None
        self.setID(ID)
        self.error = Error(**kwargs)

    def setResult(self, **kwargs):
        self.result = Result(**kwargs)

    def setError(self, section=None):
        if section is not None:
            if self.error.setSection(section):
                return True
            else:
                return False

    def setID(self, ID):
        if ID is None or ID == "":
            self.id = str(uuid.uuid4())
        else:
            self.id = ID

    def jsonWrite(self):
        try:
            #jsonOut =  jsonlib2.write(self, default=lambda o: o.__dict__,sort_keys=False, indent=4,escape_slash=False)
            jsonOut = jsonpickle.encode(self, unpicklable=False)
            #jsonOut = ujson.dumps(self, ensure_ascii=False, indent=4)
            #jsonOut2 = simplejson.dumps(pippo, ensure_ascii=False, indent=4)
            return jsonOut
        except BaseException as error:
            logging.getLogger(__name__).error("Error on json encoding %s" % (error.message))
            return False

class RequestHandler(tornado.web.RequestHandler):

    @property
    def executor(self):
        return self.application.executor

    def compute_etag(self):
        return None

    def write_error(self, status_code, errorcode = '3', **kwargs):
        self.set_header('Content-Type', 'application/json; charset=UTF-8')
        self.set_status(status_code)

        # debug info
        if self.settings.get("serve_traceback") and "exc_info" in kwargs:
            debugTmp = ""
            for line in traceback.format_exception(*kwargs["exc_info"]):
                debugTmp += line
            getResponse = ResponseObj(debugMessage=debugTmp,httpcode=status_code,devMessage=self._reason)
        else:
            getResponse = ResponseObj(httpcode=status_code,devMessage=self._reason)

        getResponse.setError(errorcode)
        getResponse.setResult()

        self.write(getResponse.jsonWrite())
        self.finish()

class StaticFileHandler(tornado.web.StaticFileHandler):

    def compute_etag(self):
        return None

    def write_error(self, status_code, errorcode = '3', **kwargs):
        self.set_header('Content-Type', 'application/json; charset=UTF-8')
        self.set_status(status_code)

        # debug info
        if self.settings.get("serve_traceback") and "exc_info" in kwargs:
            debugTmp = ""
            for line in traceback.format_exception(*kwargs["exc_info"]):
                debugTmp += line
            getResponse = ResponseObj(debugMessage=debugTmp,httpcode=status_code,devMessage=self._reason)
        else:
            getResponse = ResponseObj(httpcode=status_code,devMessage=self._reason)

        getResponse.setError(errorcode)
        getResponse.setResult()

        self.write(getResponse.jsonWrite())
        self.finish()

