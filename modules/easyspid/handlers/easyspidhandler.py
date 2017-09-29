import os
from response import ResponseObj
from response import RequestHandler
from request import RequestObjNew
import tornado.web
import traceback
import tornado.gen
import tornado.ioloop
import tornado.concurrent
import tornado.httpclient
import logging
from lib.customException import ApplicationException
import globalsObj
import re
import easyspid.lib.easyspid
import easyspid.lib.database
import easyspid.lib.utils
from easyspid.lib.utils import Saml2_Settings
from onelogin.saml2.constants import OneLogin_Saml2_Constants
from onelogin.saml2.idp_metadata_parser import OneLogin_Saml2_IdPMetadataParser
from onelogin.saml2.authn_request import OneLogin_Saml2_Authn_Request
from onelogin.saml2.utils import OneLogin_Saml2_Utils
from onelogin.saml2.auth import OneLogin_Saml2_Auth
from onelogin.saml2.response import OneLogin_Saml2_Response
import xml.etree.ElementTree
from onelogin.saml2.errors import OneLogin_Saml2_ValidationError
import asyncio

class easyspidHandler(RequestHandler):

    def __init__(self, *args, **kwds):
        super(RequestHandler, self).__init__(*args, **kwds)
        self.dbobjSaml = globalsObj.DbConnections['samlDb']
        self.dbobjJwt = globalsObj.DbConnections['jwtDb']
        self.routing = None

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
        x_real_ip = self.request.headers.get("X-Real-IP")
        self.remote_ip = x_real_ip or self.request.remote_ip

        self.set_header('Content-Type', 'application/json; charset=UTF-8')
        self.set_default_headers()

        #### task da eseguire per il get
        # build metadata
        spbuild = re.compile("^/api/prvd/([^/]+)/metadata/build$")

        # read metadata
        spget = re.compile("^/api/prvd/([^/]+)/metadata$")

        # get providers list
        prvd = re.compile("^/api/prvd$")

        # build authn request
        athn = re.compile("^/api/prvd/([^/]+)/authnreq/build")

        # login authn request
        loginauth = re.compile("^/api/prvd/([^/]+)/authnreq/login")

        if spbuild.search(self.request.path):
            sp = spbuild.search(self.request.path).group(1)
            response_obj = await asyncio.get_event_loop().run_in_executor(None, self.buildMetadata, sp)
            #response_obj = await tornado.platform.asyncio.to_tornado_future(fut)

        elif spget.search(self.request.path):
            sp = spget.search(self.request.path).group(1)
            response_obj = await asyncio.get_event_loop().run_in_executor(None, self.getMetadata, sp)
            #response_obj = await tornado.platform.asyncio.to_tornado_future(fut)

        elif prvd.search(self.request.path):
            response_obj = await asyncio.get_event_loop().run_in_executor(None, self.getProviders)
            #response_obj = await tornado.platform.asyncio.to_tornado_future(fut)

        elif athn.search(self.request.path):
            sp = athn.search(self.request.path).group(1)
            idp = super(self.__class__, self).get_argument('idp')
            attributeIndex = super(self.__class__, self).get_argument('attrindex')
            binding = super(self.__class__, self).get_argument('binding')
            response_obj = await asyncio.get_event_loop().run_in_executor(None, self.buildAthnReq, sp, idp, attributeIndex, binding)
            #response_obj = await tornado.platform.asyncio.to_tornado_future(fut)

        elif loginauth.search(self.request.path):
            sp = loginauth.search(self.request.path).group(1)
            idp = super(self.__class__, self).get_argument('idp')
            attributeIndex = super(self.__class__, self).get_argument('attrindex')
            binding = super(self.__class__, self).get_argument('binding')
            srelay = super(self.__class__, self).get_argument('srelay')
            response_obj = await asyncio.get_event_loop().run_in_executor(None, self.loginAuthnReq, sp, idp,attributeIndex, binding, srelay)
            #response_obj = await tornado.platform.asyncio.to_tornado_future(fut)

            if response_obj.error.httpcode == 200 and binding == 'redirect':
                self.writeLog(response_obj)
                self.set_header('Content-Type', 'text/html; charset=UTF-8')
                self.set_header('Location', response_obj.result.redirectTo)
                self.set_status(303)
                #self.write(response_obj.jsonWrite())
                self.finish()
                return

            elif response_obj.error.httpcode == 200 and binding == 'post':
                self.writeLog(response_obj)
                self.set_header('Content-Type', 'text/html; charset=UTF-8')
                self.set_status(response_obj.error.httpcode)
                self.write(response_obj.result.postTo)
                self.finish()
                return

        # self.set_status(response_obj.error.httpcode)
        # self.write(response_obj.jsonWrite())
        # self.finish()

        self.writeLog(response_obj)
        self.writeResponse(response_obj)

    #@tornado.gen.coroutine
    async def post(self):
        x_real_ip = self.request.headers.get("X-Real-IP")
        self.remote_ip = x_real_ip or self.request.remote_ip

        self.set_header('Content-Type', 'application/json; charset=UTF-8')
        self.set_default_headers()

        # sp metadata verify
        metadataVerify = re.compile("^/api/prvd/([^/]+)/metadata/verify$")

        # validate assertion sign
        validateAssertion = re.compile("^/api/assertion/validate$")

        # verify authn request
        authnverify = re.compile("^/api/prvd/([^/]+)/authnreq/verify")

        # process saml response
        response = re.compile("^/api/prvd/([^/]+)/consume")

        if metadataVerify.search(self.request.path):
            sp = metadataVerify.search(self.request.path).group(1)
            response_obj = await asyncio.get_event_loop().run_in_executor(None, self.verifySpMetadata, sp)
            #response_obj = await tornado.platform.asyncio.to_tornado_future(fut)

        elif validateAssertion.search(self.request.path):
            response_obj = await asyncio.get_event_loop().run_in_executor(None, self.validateAssertion)
            #response_obj = await tornado.platform.asyncio.to_tornado_future(fut)

        elif authnverify.search(self.request.path):
            sp = authnverify.search(self.request.path).group(1)
            response_obj = await asyncio.get_event_loop().run_in_executor(None, self.verifyAuthnRequest, sp)
            #response_obj = await tornado.platform.asyncio.to_tornado_future(fut)

        elif response.search(self.request.path):
            sp = response.search(self.request.path).group(1)
            response_obj = await asyncio.get_event_loop().run_in_executor(None, self.processResponse, sp)
            #response_obj = await tornado.platform.asyncio.to_tornado_future(fut)

            if response_obj.error.httpcode == 200:
                self.writeLog(response_obj)
                self.set_header('Content-Type', 'text/html; charset=UTF-8')
                self.set_status(response_obj.error.httpcode)
                self.write(response_obj.result.postTo)
                self.finish()
                return

        self.writeLog(response_obj)
        self.writeResponse(response_obj)

    def options(self):
        # no body
        self.set_status(204)
        self.finish()

    def writeResponse(self, response_obj):

        # if self.routing is None:
        #     self.set_status(response_obj.error.httpcode)
        #     self.write(response_obj.jsonWrite())
        #     self.finish()
        # else:
        #     self.client = tornado.httpclient.AsyncHTTPClient()
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

        log_request = self.dbobjSaml.makeQuery("EXECUTE log_request(%s, %s, %s, %s)",
                        [self.request.method,
                         self.request.protocol + "://" + self.request.host + self.request.uri,
                         body,
                         remote_ip],
                        type = self.dbobjSaml.stmts['log_request']['pool'], close = True, fetch=False)

        log_response = self.dbobjSaml.makeQuery("EXECUTE log_response(%s, %s, %s, %s)",
                        [response_obj.error.httpcode,
                         self.request.protocol + "://" + self.request.host + self.request.uri,
                         response_obj.jsonWrite(),
                         remote_ip],
                        type = self.dbobjSaml.stmts['log_response']['pool'], close = True, fetch=False)

        return

    def buildMetadata(self, sp, dbSave = True):
        x_real_ip = self.request.headers.get("X-Real-IP")
        remote_ip = x_real_ip or self.request.remote_ip

        try:
            """ This will be executed in `executor` pool. """
            #self.connSaml = easyspid.lib.database.Database(globalsObj.DbConnections['samlDbPollMaster']['pool'])
            #self.connJwt = jwtoken.lib.database.Database(globalsObj.DbConnections['jwtDbPollSlave']['pool'])
            sp_settings = easyspid.lib.easyspid.spSettings(sp, close = True)

            if sp_settings['error'] == 0 and sp_settings['result'] != None:
                # genera risposta tutto ok
                spSettings = Saml2_Settings(sp_settings['result'])
                metadata = spSettings.get_sp_metadata()
                metadata = str(metadata,'utf-8')

                ## insert into DB
                if dbSave:
                    #wrtMetada = globalsObj.DbConnections['samlMaster'].write_assertion(metadata, sp=sp, client=self.remote_ip)
                    #conn = easyspid.lib.database.Database(globalsObj.DbConnections['samlMasterdsn'])
                    #wrtMetada = self.connSaml.write_assertion(metadata, sp=sp, client=self.remote_ip, close = True)
                    wrtMetada = self.dbobjSaml.makeQuery("EXECUTE write_assertion(%s, %s, %s, %s)",
                        [metadata, sp, None, remote_ip],type = self.dbobjSaml.stmts['write_assertion']['pool'], close = True)

                    if wrtMetada['error'] == 0:
                        #jwt = self.connJwt.getTokenByCod(wrtMetada['result']['cod_token'], close = True)
                        jwt = self.dbobjJwt.makeQuery("EXECUTE get_token_by_cod(%s)",
                        [wrtMetada['result']['cod_token']],type = self.dbobjJwt.stmts['get_token_by_cod']['pool'], close = True)

                        response_obj = ResponseObj(httpcode=200, ID = wrtMetada['result']['ID_assertion'])
                        response_obj.setError('200')
                        response_obj.setResult(metadata = metadata, jwt=jwt['result']['token'],
                                               idassertion=wrtMetada['result']['ID_assertion'])
                    else:
                        response_obj = ResponseObj(httpcode=500, debugMessage=wrtMetada['result'])
                        response_obj.setError("easyspid105")
                        #responsejson = response_obj.jsonWrite()
                        logging.getLogger(__name__).error('Exception',exc_info=True)
                else:
                    response_obj = ResponseObj(httpcode=200)
                    response_obj.setError('200')
                    response_obj.setResult(metadata = metadata, jwt="")

            elif sp_settings['error'] == 0 and sp_settings['result'] == None:
                response_obj = ResponseObj(httpcode=404)
                response_obj.setError('easyspid101')

            elif sp_settings['error'] > 0:
                response_obj = ResponseObj(httpcode=500, debugMessage=sp_settings['result'])
                response_obj.setError("easyspid105")

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
            logging.getLogger(__name__).warning('easyspid/buildMetadata handler executed')

        return response_obj

    def getMetadata(self, sp):
        try:
            """ This will be executed in `executor` pool. """
            #sp_metadata = connSaml.get_prvd_metadta(sp, close = True)
            sp_metadata  = self.dbobjSaml.makeQuery("EXECUTE get_prvd_metadta(%s)",
                        [sp],type = self.dbobjSaml.stmts['get_prvd_metadta']['pool'])

            if sp_metadata['error'] == 0 and sp_metadata['result'] != None:
                # genera risposta tutto ok
                metadata = sp_metadata['result']['xml']
                public_key = sp_metadata['result']['public_key']
                fingerprint = sp_metadata['result']['fingerprint']
                fingerprintalg = sp_metadata['result']['fingerprintalg']
                private_key = sp_metadata['result']['private_key']

                response_obj = ResponseObj(httpcode=200)
                response_obj.setError('200')
                response_obj.setResult(metadata = metadata, x509cert = public_key, key = private_key,
                            x509certFingerPrint = fingerprint, fingerPrintAlg = fingerprintalg)

            elif sp_metadata['error'] == 0 and sp_metadata['result'] == None:
                response_obj = ResponseObj(httpcode=404)
                response_obj.setError('easyspid101')

            elif sp_metadata['error'] > 0:
                response_obj = ResponseObj(httpcode=500, debugMessage=sp_metadata['result'])
                response_obj.setError("easyspid105")

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
            logging.getLogger(__name__).warning('easyspid/getMetadata handler executed')

        return response_obj

    def getProviders(self, active = True):
        try:
            """ This will be executed in `executor` pool. """
            #sp_metadata = connSaml.get_providers(active, close=True)
            sp_metadata  = self.dbobjSaml.makeQuery("EXECUTE get_providers(%s)",
                        [active],type = self.dbobjSaml.stmts['get_providers']['pool'])

            if sp_metadata['error'] == 0 and sp_metadata['result'] != None:
                tmp = list()
                for index, record in enumerate(sp_metadata['result']):
                    tmp.append({'code': record['cod_provider'],
                                  'name': record['name'],
                                  'type': record['type'],
                                  'description': record['description']})
                    # genera risposta tutto ok

                response_obj = ResponseObj(httpcode=200)
                response_obj.setError('200')
                response_obj.setResult(providers = tmp)

            elif sp_metadata['error'] == 0 and sp_metadata['result'] == None:
                response_obj = ResponseObj(httpcode=404)
                response_obj.setError('easyspid101')

            elif sp_metadata['error'] > 0:
                response_obj = ResponseObj(httpcode=500, debugMessage=sp_metadata['result'])
                response_obj.setError("easyspid105")

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
            logging.getLogger(__name__).warning('easyspid/getProviders handler executed')

        return response_obj

    def verifySpMetadata(self, sp):
        try:
            #connSaml = easyspid.lib.database.Database(globalsObj.DbConnections['samlDbPollSlave']['pool'])
            #sp_settings = easyspid.lib.easyspid.spSettings(sp)
            sp_settings = easyspid.lib.easyspid.spSettings(sp, close = True)

            temp = RequestObjNew(self.request.body)
            if temp.error["code"] == 2:
                response_obj = ResponseObj(debugMessage=temp.error["message"], httpcode=400)
                response_obj.setError('400')
                logging.getLogger(__name__).error('Validation error. Json input error')
                return response_obj

            elif temp.error["code"] > 0:
                raise tornado.web.HTTPError(httpcode=503, log_message=temp.error["message"])

            metadata = temp.request['metadata']

            if sp_settings['error'] == 0 and sp_settings['result'] != None:
                # genera risposta tutto ok

                spSettings = Saml2_Settings(sp_settings['result'])

                chk = spSettings.validate_metadata(metadata,
                        fingerprint = sp_settings['result']['sp']['x509cert_fingerprint'],
                        fingerprintalg = sp_settings['result']['sp']['x509cert_fingerprintalg'],
                        validatecert=False)

                if not chk['schemaValidate']:
                    response_obj = ResponseObj(httpcode=401)
                    response_obj.setError('easyspid104')
                    response_obj.setResult(metadataValidate = chk)

                elif not chk['signCheck']:
                    response_obj = ResponseObj(httpcode=401)
                    response_obj.setError('easyspid106')
                    response_obj.setResult(metadataValidate = chk)

                elif chk['schemaValidate'] and chk['signCheck']:
                    response_obj = ResponseObj(httpcode=200)
                    response_obj.setError('200')
                    response_obj.setResult(metadataValidate = chk)

            elif sp_settings['error'] == 0 and sp_settings['result'] == None:
                response_obj = ResponseObj(httpcode=404)
                response_obj.setError('easyspid101')

            elif sp_settings['error'] > 0:
                response_obj = ResponseObj(httpcode=500, debugMessage=sp_settings['result'])
                response_obj.setError("easyspid105")

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
            logging.getLogger(__name__).warning('easyspid/verifySpMetadata handler executed')

        response_obj.setID(temp.id)
        return response_obj

    def validateAssertion(self):

        try:

            temp = RequestObjNew(self.request.body)
            if temp.error["code"] == 2:
                response_obj = ResponseObj(debugMessage=temp.error["message"], httpcode=400)
                response_obj.setError('400')
                logging.getLogger(__name__).error('Validation error. Json input error')
                return response_obj

            elif temp.error["code"] > 0:
                raise tornado.web.HTTPError(httpcode=503, log_message=temp.error["message"])

            prvd = temp.request['provider']
            assertion = temp.request['assertion']

            if prvd != "":
                prvdSignature  = self.dbobjSaml.makeQuery("EXECUTE get_signature(%s)",
                            [prvd],type = self.dbobjSaml.stmts['get_signature']['pool'])

                if prvdSignature['error'] == 0 and prvdSignature['result'] != None:
                    certFingerprint = prvdSignature['result']['fingerprint']
                    certFingerprintalg = prvdSignature['result']['fingerprintalg']

                elif prvdSignature['error'] == 0 and prvdSignature['result'] == None:
                    response_obj = ResponseObj(httpcode=404)
                    response_obj.setError('easyspid112')
                    return response_obj

                elif prvdSignature['error'] > 0:
                    response_obj = ResponseObj(httpcode=500, debugMessage=prvdSignature['result'])
                    response_obj.setError("easyspid105")
                    return response_obj

            elif prvd == "":
                certFingerprint = None
                certFingerprintalg = None

            chk = easyspid.lib.utils.validateAssertion(assertion, fingerprint=certFingerprint, fingerprintalg=certFingerprintalg)

            if not chk['schemaValidate']:
                response_obj = ResponseObj(httpcode=401)
                response_obj.setError('easyspid104')
                response_obj.setResult(assertionChk = chk)

            elif not chk['signCheck']:
                response_obj = ResponseObj(httpcode=401)
                response_obj.setError('easyspid106')
                response_obj.setResult(assertionChk = chk)

            elif chk['schemaValidate'] and chk['signCheck']:
                response_obj = ResponseObj(httpcode=200)
                response_obj.setError('200')
                response_obj.setResult(assertionChk = chk)

        except tornado.web.MissingArgumentError as error:
            response_obj = ResponseObj(debugMessage=error.log_message, httpcode=error.status_code,
                                       devMessage=error.log_message)
            response_obj.setError(str(error.status_code))
            logging.getLogger(__name__).error('%s'% error,exc_info=True)

        except ApplicationException as inst:
            response_obj = ResponseObj(httpcode=500,  debugMessage=inst)
            response_obj.setError(inst.code)
            #responsejson = response_obj.jsonWrite()
            logging.getLogger(__name__).error('Exception',exc_info=True)

        except Exception as inst:
            response_obj = ResponseObj(httpcode=500, debugMessage=inst)
            response_obj.setError('500')
            logging.getLogger(__name__).error('Exception',exc_info=True)

        finally:
            logging.getLogger(__name__).warning('easyspid/validateAssertion handler executed')

        response_obj.setID(temp.id)
        return response_obj

    def buildAthnReq(self, sp, idp, attributeIndex, binding='redirect', signed = True):
        x_real_ip = self.request.headers.get("X-Real-IP")
        remote_ip = x_real_ip or self.request.remote_ip

        try:
            bindingMap = {'redirect':OneLogin_Saml2_Constants.BINDING_HTTP_REDIRECT,
                          'post': OneLogin_Saml2_Constants.BINDING_HTTP_POST}

            #connSaml = easyspid.lib.database.Database(globalsObj.DbConnections['samlDbPollMaster']['pool'])
            #connJwt = jwtoken.lib.database.Database(globalsObj.DbConnections['jwtDbPollSlave']['pool'])
            #sp_settings = easyspid.lib.easyspid.spSettings(sp, idp, conn=self.connSaml, close=False)
            sp_settings = easyspid.lib.easyspid.spSettings(sp, idp, binding=bindingMap[binding], close = True)

            if sp_settings['error'] == 0 and sp_settings['result'] != None:

                # idp_data = OneLogin_Saml2_IdPMetadataParser.parse(idp_metadata.result.metadata,
                #         required_sso_binding=bindingMap[binding], required_slo_binding=bindingMap[binding])
                # idp_settings = idp_data['idp']

                # get sp metadata to read attributeIndex location
                sp_metadata = self.buildMetadata(sp, dbSave=False)
                sp_metadata = sp_metadata.result.metadata
                ns = {'md0': OneLogin_Saml2_Constants.NS_MD, 'md1': OneLogin_Saml2_Constants.NS_SAML}
                parsedMetadata = xml.etree.ElementTree.fromstring(sp_metadata)
                attributeConsumingService = parsedMetadata.find("md0:SPSSODescriptor/md0:AssertionConsumerService[@index='%s']" %
                                                                attributeIndex, ns)
                if attributeConsumingService == None:
                    response_obj = ResponseObj(httpcode=404)
                    response_obj.setError('easyspid102')
                    return response_obj

                spSettings = Saml2_Settings(sp_settings['result'])

                key = spSettings.get_sp_key()
                cert = spSettings.get_sp_cert()
                sign_alg = (spSettings.get_security_data())['signatureAlgorithm']
                digest = (spSettings.get_security_data())['digestAlgorithm']

                # build auth request
                authn_request = OneLogin_Saml2_Authn_Request(spSettings, force_authn=True, is_passive=False, set_nameid_policy=True)
                authn_request_xml = authn_request.get_xml()

                ## inserisci attribute index
                ns = {'md0': OneLogin_Saml2_Constants.NS_MD, 'md1': OneLogin_Saml2_Constants.NS_SAML}
                xml.etree.ElementTree.register_namespace('md0', OneLogin_Saml2_Constants.NS_MD)
                xml.etree.ElementTree.register_namespace('md1', OneLogin_Saml2_Constants.NS_SAML)

                parsedMetadata = xml.etree.ElementTree.fromstring(authn_request_xml)
                parsedMetadata.attrib['AttributeConsumingServiceIndex'] = attributeIndex
                parsedMetadata.attrib['AssertionConsumerServiceURL'] = attributeConsumingService.attrib['Location']

                issuer = parsedMetadata.find("md1:Issuer", ns)
                issuer.set("Format", "urn:oasis:names:tc:SAML:2.0:nameid-format:entity")
                issuer.set("NameQualifier", (spSettings.get_sp_data())['entityId'])

                ## inserisci attributi del nodo isuuer
                authn_request_xml = xml.etree.ElementTree.tostring(parsedMetadata, encoding="unicode")
                if signed:
                    authn_request_signed = OneLogin_Saml2_Utils.add_sign(authn_request_xml, key, cert, debug=False,
                                        sign_algorithm=sign_alg, digest_algorithm=digest)
                    authn_request_signed = str(authn_request_signed,'utf-8')
                else:
                    authn_request_signed = authn_request_xml

                ## insert into DB
                #wrtAuthn = self.dbobjSaml.makeQuery("EXECUTE write_assertion(%s, %s, %s, %s)",
                #        [authn_request_signed, sp, idp, self.remote_ip],type = self.dbobjSaml.stmts['write_assertion']['pool'], close = True)
                wrtAuthn = self.dbobjSaml.makeQuery("EXECUTE write_assertion(%s, %s, %s, %s)",
                        [authn_request_signed, sp, idp, remote_ip],type = self.dbobjSaml.stmts['write_assertion']['pool'], close = True)
                if wrtAuthn['error'] == 0:
                    #jwt = self.connJwt.getTokenByCod(wrtAuthn['result']['cod_token'], close=True)
                    jwt = self.dbobjJwt.makeQuery("EXECUTE get_token_by_cod(%s)",
                        [wrtAuthn['result']['cod_token']],type = self.dbobjJwt.stmts['get_token_by_cod']['pool'], close = True)
                    response_obj = ResponseObj(httpcode=200, ID = wrtAuthn['result']['ID_assertion'])
                    response_obj.setError('200')
                    response_obj.setResult(authnrequest = authn_request_signed, jwt=jwt['result']['token'],
                                           idassertion=wrtAuthn['result']['ID_assertion'])
                else:
                    response_obj = ResponseObj(httpcode=500, debugMessage=wrtAuthn['result'])
                    response_obj.setError("easyspid105")
                    #responsejson = response_obj.jsonWrite()
                    logging.getLogger(__name__).error('Exception',exc_info=True)

            elif sp_settings['error'] == 0 and sp_settings['result'] == None:
                response_obj = ResponseObj(httpcode=404)
                response_obj.setError('easyspid101')

            elif sp_settings['error'] > 0:
                response_obj = ResponseObj(httpcode=500, debugMessage=sp_settings['result'])
                response_obj.setError("easyspid105")

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
            logging.getLogger(__name__).warning('easyspid/buildAthnReq handler executed')

        return response_obj

    def verifyAuthnRequest(self, provider):
        try:
            #connSaml = easyspid.lib.database.Database(globalsObj.DbConnections['samlSlavedsn'])
            #prvd_settings = easyspid.lib.easyspid.spSettings(provider, conn=connSaml)
            prvd_settings = easyspid.lib.easyspid.spSettings(provider, close = True)

            temp = RequestObjNew(self.request.body)
            if temp.error["code"] == 2:
                response_obj = ResponseObj(debugMessage=temp.error["message"], httpcode=400)
                response_obj.setError('400')
                logging.getLogger(__name__).error('Validation error. Json input error')
                return response_obj

            elif temp.error["code"] > 0:
                raise tornado.web.HTTPError(httpcode=503, log_message=temp.error["message"])

            authn_request_signed = temp.request['authnrequest']

            if prvd_settings['error'] == 0 and prvd_settings['result'] != None:
                prvdSettings = Saml2_Settings(prvd_settings['result'])

                #chk = prvdSettings.validate_authnreq_sign(authn_request_signed, validatecert=False)
                chk = easyspid.lib.utils.validateAssertion(authn_request_signed,
                                prvd_settings['result']['sp']['x509cert_fingerprint'],
                                prvd_settings['result']['sp']['x509cert_fingerprintalg'])

                #if len(chk['schemaValidate']) > 0:
                if not chk['schemaValidate']:
                    response_obj = ResponseObj(httpcode=401)
                    response_obj.setError('easyspid104')
                    response_obj.setResult(authnValidate = chk)

                elif not chk['signCheck']:
                    response_obj = ResponseObj(httpcode=401)
                    response_obj.setError('easyspid106')
                    response_obj.setResult(authnValidate = chk)

                #elif len(chk['schemaValidate']) == 0 and chk['signCheck']:
                elif chk['schemaValidate'] and chk['signCheck']:
                    response_obj = ResponseObj(httpcode=200)
                    response_obj.setError('200')
                    response_obj.setResult(authnValid = chk)

            elif prvd_settings['error'] == 0 and prvd_settings['result'] == None:
                response_obj = ResponseObj(httpcode=404)
                response_obj.setError('easyspid101')

            elif prvd_settings['error'] > 0:
                response_obj = ResponseObj(httpcode=500, debugMessage=prvd_settings['result'])
                response_obj.setError("easyspid105")

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
            logging.getLogger(__name__).warning('easyspid/verifyAuthnRequest handler executed')

        response_obj.setID(temp.id)
        return response_obj

    def loginAuthnReq(self, sp, idp, attributeIndex, binding, srelay_cod):
        try:
            # buil authn request
            if binding == 'redirect':
                authn_request = self.buildAthnReq(sp, idp, attributeIndex, signed=False)
            elif binding == 'post':
                authn_request = self.buildAthnReq(sp, idp, attributeIndex, signed=True)

            bindingMap = {'redirect':OneLogin_Saml2_Constants.BINDING_HTTP_REDIRECT,
                          'post': OneLogin_Saml2_Constants.BINDING_HTTP_POST}

            # get sp settings
            #connSaml = easyspid.lib.database.Database(globalsObj.DbConnections['samlMasterdsn'])
            #sp_settings = easyspid.lib.easyspid.spSettings(sp, conn=connSaml)
            sp_settings = easyspid.lib.easyspid.spSettings(sp, close = True)

            # get idp metadata
            idp_metadata = self.getMetadata(idp)

            # get relay state
            #srelay = connSaml.get_services(srelay_cod, active=True)
            srelay  = self.dbobjSaml.makeQuery("EXECUTE get_service(%s, %s, %s)",
                        [True, srelay_cod, sp],type = self.dbobjSaml.stmts['get_service']['pool'])

            if srelay['error'] == 0 and srelay['result'] == None:
                response_obj = ResponseObj(httpcode=404)
                response_obj.setError('easyspid113')
                return response_obj

            elif srelay['error'] > 0:
                response_obj = ResponseObj(httpcode=500, debugMessage=sp_settings['result'])
                response_obj.setError("easyspid105")
                return response_obj

            if (sp_settings['error'] == 0 and sp_settings['result'] != None
                and idp_metadata.error.code == '200' and authn_request.error.code == '200'):

                idp_data = OneLogin_Saml2_IdPMetadataParser.parse(idp_metadata.result.metadata,
                        required_sso_binding=bindingMap[binding], required_slo_binding=bindingMap[binding])
                idp_settings = idp_data['idp']

                # fake authn_request
                req = {"http_host": "",
                    "script_name": "",
                    "server_port": "",
                    "get_data": "",
                    "post_data": ""}

                settings = sp_settings['result']
                if 'entityId' in idp_settings:
                    settings['idp']['entityId'] = idp_settings['entityId']
                if 'singleLogoutService' in idp_settings:
                    settings['idp']['singleLogoutService'] = idp_settings['singleLogoutService']
                if 'singleSignOnService' in idp_settings:
                    settings['idp']['singleSignOnService'] = idp_settings['singleSignOnService']
                if 'x509cert' in idp_settings:
                    settings['idp']['x509cert'] = idp_settings['x509cert']

                auth = OneLogin_Saml2_Auth(req, sp_settings['result'])
                spSettings = Saml2_Settings(sp_settings['result'])

                sign_alg = (spSettings.get_security_data())['signatureAlgorithm']

                # build login message
                # redirect binding
                if binding == 'redirect':
                    saml_request = OneLogin_Saml2_Utils.deflate_and_base64_encode(authn_request.result.authnrequest)
                    parameters = {'SAMLRequest': saml_request}
                    parameters['RelayState'] = srelay['result']['relay_state']
                    auth.add_request_signature(parameters, sign_alg)
                    redirectLocation = auth.redirect_to(auth.get_sso_url(), parameters)

                    response_obj = ResponseObj(httpcode=200)
                    response_obj.setError('200')
                    response_obj.setResult(redirectTo = redirectLocation, jwt=authn_request.result.jwt)

                # POST binding
                elif binding == 'post':
                    #authn_request_signed = self.buildAthnReq(sp, idp, attributeIndex, signed=True)
                    saml_request_signed = OneLogin_Saml2_Utils.b64encode(authn_request.result.authnrequest)
                    relay_state = OneLogin_Saml2_Utils.b64encode(srelay['result']['relay_state'])
                    idpsso = idp_settings['singleSignOnService']['url']

                    try:
                        with open(os.path.join(globalsObj.rootFolder, globalsObj.easyspid_postFormPath), 'r') as myfile:
                            post_form = myfile.read().replace('\n', '')
                    except:
                        with open(globalsObj.easyspid_postFormPath, 'r') as myfile:
                            post_form = myfile.read().replace('\n', '')

                    post_form = post_form.replace("%IDPSSO%",idpsso)
                    post_form = post_form.replace("%AUTHNREQUEST%",saml_request_signed)
                    post_form = post_form.replace("%RELAYSTATE%",relay_state)

                    response_obj = ResponseObj(httpcode=200)
                    response_obj.setError('200')
                    response_obj.setResult(postTo = post_form, jwt=authn_request.result.jwt)

            elif sp_settings['error'] == 0 and sp_settings['result'] == None:
                response_obj = ResponseObj(httpcode=404)
                response_obj.setError('easyspid101')

            elif sp_settings['error'] > 0:
                response_obj = ResponseObj(httpcode=500, debugMessage=sp_settings['result'])
                response_obj.setError("easyspid105")

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
            logging.getLogger(__name__).warning('easyspid/loginAuthnReq handler executed')

        return response_obj

    def processResponse(self, sp, chkTime=False):
        x_real_ip = self.request.headers.get("X-Real-IP")
        remote_ip = x_real_ip or self.request.remote_ip

        try:
            #connSaml = easyspid.lib.database.Database(globalsObj.DbConnections['samlMasterdsn'])
            #connJwt = jwtoken.lib.database.Database(globalsObj.DbConnections['jwtSlavedsn'])

            # get response and Relay state
            responsePost = self.get_argument('SAMLResponse')
            srelayPost = self.get_argument('RelayState')

            # decode saml response to get idp code by entityId attribute
            response = responsePost
            try:
                 response = OneLogin_Saml2_Utils.decode_base64_and_inflate(responsePost)
            except Exception:
                 response = OneLogin_Saml2_Utils.b64decode(responsePost)
            try:
                 response = OneLogin_Saml2_Utils.b64decode(responsePost)
            except Exception:
                 pass

            #decode Relay state
            srelay = srelayPost
            try:
                 srelay = OneLogin_Saml2_Utils.decode_base64_and_inflate(srelayPost)
            except Exception:
                 pass
            try:
                 srelay = OneLogin_Saml2_Utils.b64decode(srelayPost)
            except Exception:
                 pass

            try:
                service = self.dbobjSaml.makeQuery("EXECUTE get_service(%s, %s, %s)",
                        [True, srelay, sp],type = self.dbobjSaml.stmts['get_service']['pool'])

                if service['error'] == 0 and service['result'] != None:
                    # costruisci il routing
                    self.routing = dict()
                    self.routing['url'] = service['result']['url']
                    self.routing['relaystate'] = srelay

                elif service['error'] > 0:
                    response_obj = ResponseObj(httpcode=500, debugMessage=service['result'])
                    response_obj.setError("easyspid111")
                    return response_obj

            except Exception:
                pass

            ns = {'md0': OneLogin_Saml2_Constants.NS_SAMLP, 'md1': OneLogin_Saml2_Constants.NS_SAML}
            parsedResponse = xml.etree.ElementTree.fromstring(response)
            issuer = parsedResponse.find("md1:Issuer", ns)

            #idpEntityId = connSaml.get_provider_byentityid(issuer.text.strip())
            idpEntityId = self.dbobjSaml.makeQuery("EXECUTE get_provider_byentityid(%s, %s)",
                        [True, '{'+(issuer.text.strip())+'}'],type = self.dbobjSaml.stmts['get_provider_byentityid']['pool'])

            if idpEntityId['error'] == 0 and idpEntityId['result'] != None:
                idp_metadata = idpEntityId['result']['xml']
                idp = idpEntityId['result']['cod_provider']

            elif idpEntityId['error'] == 0 and idpEntityId['result'] == None:
                response_obj = ResponseObj(httpcode=404)
                response_obj.setError('easyspid103')
                return response_obj

            elif idpEntityId['error'] > 0:
                response_obj = ResponseObj(httpcode=500, debugMessage=idpEntityId['result'])
                response_obj.setError("easyspid105")
                return response_obj

            # get settings
            #sp_settings = easyspid.lib.easyspid.spSettings(sp, idp, conn=connSaml)
            sp_settings = easyspid.lib.easyspid.spSettings(sp, idp, close = True)

            if sp_settings['error'] == 0 and sp_settings['result'] != None:

                ## insert response into DB
                #wrtAuthn = connSaml.write_assertion(str(response,'utf-8'), sp, idp, client=self.remote_ip)
                wrtAuthn = self.dbobjSaml.makeQuery("EXECUTE write_assertion(%s, %s, %s, %s)",
                        [str(response,'utf-8'), sp, idp, remote_ip],type = self.dbobjSaml.stmts['write_assertion']['pool'], close = True)
                if wrtAuthn['error'] == 0:
                    #jwt = connJwt.getTokenByCod(wrtAuthn['result']['cod_token'])
                    jwt = self.dbobjJwt.makeQuery("EXECUTE get_token_by_cod(%s)",
                        [wrtAuthn['result']['cod_token']],type = self.dbobjJwt.stmts['get_token_by_cod']['pool'], close = True)

                else:
                    response_obj = ResponseObj(httpcode=500, debugMessage=wrtAuthn['result'])
                    response_obj.setError("easyspid105")
                    logging.getLogger(__name__).error('Exception',exc_info=True)
                    return response_obj

                # create settings OneLogin dict
                settings = sp_settings['result']

                #validate response sign
                prvdSettings = Saml2_Settings(sp_settings['result'])
                #chk = prvdSettings.validate_response_sign(response, validatecert=False, debug=True)
                chk = easyspid.lib.utils.validateAssertion(response,
                                sp_settings['result']['idp']['x509cert_fingerprint'],
                                sp_settings['result']['idp']['x509cert_fingerprintalg'])

                #if len(chk['schemaValidate']) > 0:
                if not chk['schemaValidate']:
                    response_obj = ResponseObj(httpcode=401)
                    response_obj.setError('easyspid104')
                    response_obj.setResult(responseValidate = chk)
                    return response_obj

                elif not chk['signCheck']:
                    response_obj = ResponseObj(httpcode=401)
                    response_obj.setError('easyspid106')
                    response_obj.setResult(responseValidate = chk)
                    return response_obj

                #elif len(chk['schemaValidate']) == 0 and chk['signCheck']:
                elif chk['schemaValidate'] and chk['signCheck']:
                    response_obj = ResponseObj(httpcode=200, ID = wrtAuthn['result']['ID_assertion'])
                    response_obj.setError('200')
                    #response_obj.setResult(responseValidate = chk)

                OneLoginResponse = OneLogin_Saml2_Response(prvdSettings, responsePost)

                #check status code
                try:
                    OneLoginResponse.check_status()
                except OneLogin_Saml2_ValidationError as error:
                    response_obj = ResponseObj(httpcode=401, debugMessage=error.args[0])
                    response_obj.setError('easyspid107')
                    return response_obj

                #check time
                if chkTime:
                    try:
                        OneLoginResponse.validate_timestamps(raise_exceptions=True)
                    except OneLogin_Saml2_ValidationError as error:
                        response_obj = ResponseObj(httpcode=401, debugMessage=error.args[0])
                        response_obj.setError('easyspid108')
                        return response_obj

                #check audience
                audience = OneLoginResponse.get_audiences()
                if not settings['sp']['entityId'] in OneLoginResponse.get_audiences():
                    response_obj = ResponseObj(httpcode=401, debugMessage=OneLoginResponse.get_audiences())
                    response_obj.setError('easyspid109')
                    return response_obj

                #check inresponse to
                inResponseTo = OneLoginResponse.document.get('InResponseTo', None)
                #inResponseChk = connSaml.chk_idAssertion(inResponseTo)
                inResponseChk = self.dbobjSaml.makeQuery("EXECUTE chk_idAssertion(%s)",
                        [inResponseTo],type = self.dbobjSaml.stmts['chk_idAssertion']['pool'], close = True)
                if inResponseChk['error'] == 0 and inResponseChk['result'] == None:
                    response_obj = ResponseObj(httpcode=401)
                    response_obj.setError('easyspid110')
                    return response_obj

                #get all attributes
                attributes = OneLoginResponse.get_attributes()

                try:
                    with open(os.path.join(globalsObj.rootFolder, globalsObj.easyspid_responseFormPath), 'r') as myfile:
                        response_form = myfile.read()
                except:
                    with open(globalsObj.easyspid_responseFormPath, 'r') as myfile:
                        response_form = myfile.read()

                response_form = response_form.replace("%URLTARGET%",self.routing['url'])
                response_form = response_form.replace("%SAMLRESPONSE%",responsePost)
                response_form = response_form.replace("%JSONRESPONSE%",OneLogin_Saml2_Utils.b64encode(response))
                response_form = response_form.replace("%RELAYSTATE%",srelayPost)

                response_obj = ResponseObj(httpcode=200, ID = wrtAuthn['result']['ID_assertion'])
                response_obj.setError('200')
                response_obj.setResult(attributes = attributes, jwt = jwt['result']['token'], responseValidate = chk,
                        response = str(response, 'utf-8'), responseBase64 = responsePost, postTo = response_form)

            elif sp_settings['error'] == 0 and sp_settings['result'] == None:
                response_obj = ResponseObj(httpcode=404)
                response_obj.setError('easyspid101')

            elif sp_settings['error'] > 0:
                response_obj = sp_settings['result']

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
            logging.getLogger(__name__).warning('easyspid/processResponse handler executed')

        return response_obj

