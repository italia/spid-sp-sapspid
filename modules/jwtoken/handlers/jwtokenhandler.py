from response import ResponseObj
from response import RequestHandler
from request import RequestObjNew

import tornado.web
import traceback
import tornado.gen
import tornado.ioloop
import tornado.concurrent
import logging
from lib.customException import ApplicationException
import globalsObj
import re
import jwtoken.lib.jwtoken
import asyncio

class jwtokenHandler(RequestHandler):

    def __init__(self, *args, **kwds):
        super(RequestHandler, self).__init__(*args, **kwds)
        self.dbobjJwt = globalsObj.DbConnections['jwtDb']

    def set_default_headers(self):
        self.set_header("Access-Control-Allow-Origin", "*")
        #self.set_header("Access-Control-Allow-Headers", "x-requested-with")
        self.set_header('Access-Control-Allow-Methods', ' POST, GET, OPTIONS')

    # gestione errore generico
    def write_error(self, status_code, **kwargs):

        # debug info
        if self.settings.get("serve_traceback") and "exc_info" in kwargs:
            debugTmp = ""
            for line in traceback.format_exception(*kwargs["exc_info"]):
                debugTmp += line
            getResponse = ResponseObj(debugMessage=debugTmp,httpcode=status_code,devMessage=self._reason)
        else:
            getResponse = ResponseObj(httpcode=status_code,devMessage=self._reason)

        self.set_header('Content-Type', 'application/json; charset=UTF-8')
        self.set_status(status_code)

        # inserisci codice errore personalizzato
        getResponse.setError('3')
        getResponse.setResult()
        self.write(getResponse.jsonWrite())
        self.finish()

    #get
    async def get(self):
        self.set_header('Content-Type', 'application/json; charset=UTF-8')
        self.set_default_headers()

        if re.match("/api/jwt/getByType", self.request.path):
            #task da eseguire per il get
            response_obj = await asyncio.get_event_loop().run_in_executor(None, self.getByType)
            #response_obj = await tornado.platform.asyncio.to_tornado_future(fut)

        elif re.match("/api/jwt/verify", self.request.path):
             #task da eseguire per il get
            response_obj = await asyncio.get_event_loop().run_in_executor(None, self.verify)
            #response_obj = await tornado.platform.asyncio.to_tornado_future(fut)

        self.writeLog(response_obj)
        self.writeResponse(response_obj)

    #@tornado.gen.coroutine
    async def post(self):
        self.set_header('Content-Type', 'application/json; charset=UTF-8')
        self.set_default_headers()

        if re.match("/api/jwt/verify", self.request.path):
            response_obj = await asyncio.get_event_loop().run_in_executor(None, self.verify)
            #response_obj = await tornado.platform.asyncio.to_tornado_future(fut)

        self.writeLog(response_obj)
        self.writeResponse(response_obj)

    def options(self):
        # no body
        self.set_status(204)
        self.finish()

    def writeResponse(self, response_obj):

        self.set_status(response_obj.error.httpcode)
        self.write(response_obj.jsonWrite())
        self.finish()

    def writeLog(self, response_obj):
        x_real_ip = self.request.headers.get("X-Real-IP")
        remote_ip = x_real_ip or self.request.remote_ip

        #insert log
        if str(self.request.body, 'utf-8') == '':
            body = None
        else:
            body = str(self.request.body, 'utf-8')

        log_request = self.dbobjJwt.makeQuery("EXECUTE log_request(%s, %s, %s, %s)",
                        [self.request.method,
                         self.request.protocol + "://" + self.request.host + self.request.uri,
                         body,
                         remote_ip],
                        type = self.dbobjJwt.stmts['log_request']['pool'], close = True, fetch=False)

        log_response = self.dbobjJwt.makeQuery("EXECUTE log_response(%s, %s, %s, %s)",
                        [response_obj.error.httpcode,
                         self.request.protocol + "://" + self.request.host + self.request.uri,
                         response_obj.jsonWrite(),
                         remote_ip],
                        type = self.dbobjJwt.stmts['log_response']['pool'], close = True, fetch=False)

        return

    #@tornado.concurrent.run_on_executor
    def getByType(self):
        try:
            jwtCode = super(self.__class__, self).get_argument('type')

            """ This will be executed in `executor` pool. """
            #connJwt = jwtoken.lib.database.Database(globalsObj.DbConnections['jwtMasterdsn'])
            #newcod_token = connJwt.createTokenByType(jwtCode)
            newcod_cod_token = self.dbobjJwt.makeQuery("EXECUTE create_token_by_type(%s)",
                        [jwtCode],type = self.dbobjJwt.stmts['create_token_by_type']['pool'], close = True)
            newcod_token = self.dbobjJwt.makeQuery("EXECUTE get_token_by_cod(%s)",
                        [newcod_cod_token['result']['cod_token']],type = self.dbobjJwt.stmts['get_token_by_cod']['pool'], close = True)

            if newcod_token['error'] == 0 and newcod_token['result'] is not None:
                # genera risposta tutto ok
                response_obj = ResponseObj(httpcode=200)
                response_obj.setError('200')
                response_obj.setResult(token = newcod_token['result']['token'])

            elif newcod_token['error'] == 0 and newcod_token['result'] is None:
                response_obj = ResponseObj(httpcode=404)
                response_obj.setError('jwtoken102')

            elif newcod_token['error'] > 1:
                response_obj = ResponseObj(debugMessage=newcod_token['result'].pgerror, httpcode=500,
                                           devMessage=("PostgreSQL error code: %s" % newcod_token['result'].pgcode))
                response_obj.setError('jwtoken105')

        except tornado.web.MissingArgumentError as error:
            response_obj = ResponseObj(debugMessage=error.log_message, httpcode=error.status_code,
                                       devMessage=error.log_message)
            response_obj.setError(str(error.status_code))
            logging.getLogger(__name__).error('%s'% error,exc_info=True)

        except ApplicationException as inst:
            response_obj = ResponseObj(httpcode=500)
            response_obj.setError(inst.code)
            #responsejson = response_obj.jsonWrite()
            logging.getLogger(__name__).error('Exception',exc_info=True)

        except Exception as inst:
            response_obj = ResponseObj(httpcode=500)
            response_obj.setError('500')
            logging.getLogger(__name__).error('Exception',exc_info=True)

        finally:
            logging.getLogger(__name__).warning('jwt/getByType handler executed')

        return response_obj

    def verify(self):
        try:
            #connJwt = jwtoken.lib.database.Database(globalsObj.DbConnections['jwtSlavedsn'])

            if self.request.method == 'GET':
                token = super(self.__class__, self).get_argument('token')

            elif  self.request.method == 'POST':
                # leggi il json della richiesta
                temp = RequestObjNew(self.request.body)

                if temp.error["code"] == 2:
                    response_obj = ResponseObj(debugMessage=temp.error["message"], httpcode=400)
                    response_obj.setError('400')
                    logging.getLogger(__name__).error('Validation error. Json input error')
                    return response_obj

                elif temp.error["code"] > 0:
                    raise tornado.web.HTTPError(httpcode=503, log_message=temp.error["message"])

                token = temp.request['token']

            #verifica = connJwt.verifyToken(token)
            verifica = self.dbobjJwt.makeQuery("EXECUTE verify_token(%s)",
                        [token],type = self.dbobjJwt.stmts['verify_token']['pool'], close = True)

            if verifica['error'] == 0:
                if verifica['result'][0] == None:
                    response_obj = ResponseObj(httpcode=404)
                    response_obj.setError('jwtoken101')

                elif verifica['result'][0]['error'] == 0:
                    response_obj = ResponseObj(httpcode=200)
                    response_obj.setError('200')
                    response_obj.setResult(jose = verifica['result'][0]['message'])

                elif verifica['result'][0]['error'] > 0:
                    response_obj = ResponseObj(httpcode=401, devMessage=(verifica['result'][0]['message']))
                    response_obj.setError('jwtoken100')

            elif verifica['error'] == 1:
                response_obj = ResponseObj(debugMessage=verifica['result'].pgerror, httpcode=500,
                                           devMessage=("PostgreSQL error code: %s" % verifica['result'].pgcode))
                response_obj.setError('jwtoken105')

        except tornado.web.MissingArgumentError as error:
            response_obj = ResponseObj(debugMessage=error.log_message, httpcode=error.status_code,
                                       devMessage=error.log_message)
            response_obj.setError(str(error.status_code))
            logging.getLogger(__name__).error('%s'% error,exc_info=True)

        except ApplicationException as inst:
            response_obj = ResponseObj(httpcode=500)
            response_obj.setError(inst.code)
            #responsejson = response_obj.jsonWrite()
            logging.getLogger(__name__).error('Exception',exc_info=True)

        except Exception as inst:
            response_obj = ResponseObj(httpcode=500)
            response_obj.setError('500')
            logging.getLogger(__name__).error('Exception',exc_info=True)

        finally:
            logging.getLogger(__name__).warning('jwt/verify handler executed')

        if  self.request.method == 'POST':
            response_obj.setID(temp.id)
        return response_obj
