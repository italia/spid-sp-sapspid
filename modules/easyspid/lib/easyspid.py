import globalsObj
import commonlib as commonlib
import easyspid.lib.database
from response import ResponseObj
from onelogin.saml2.idp_metadata_parser import OneLogin_Saml2_IdPMetadataParser
import easyspid.lib.database
import datetime
from cryptography import x509
from cryptography.hazmat.backends import default_backend
from lxml import etree
from hashlib import sha1, sha256, sha384, sha512
import base64
from onelogin.saml2.constants import OneLogin_Saml2_Constants

ESPID_ERRORS_FILE_PATH = "modules/easyspid/conf/errors.ini"
ESPID_CONFIG_FILE_PATH = "modules/easyspid/conf/easyspid.ini"

# carica le configurazioni globali e locali del modulo
easyspid_file_configuration = commonlib.configure(ESPID_CONFIG_FILE_PATH)
if globalsObj.configuration.has_option('easyspid','conf'):
    easyspid_file_configuration = commonlib.configure(globalsObj.configuration.get('easyspid','conf'),easyspid_file_configuration)

# try:
#     easyspid_file_configuration = commonlib.configure(ESPID_CONFIG_FILE_PATH, globalsObj.configuration.get('easyspid','conf'))
# except BaseException as error:
#     easyspid_file_configuration = commonlib.configure(ESPID_CONFIG_FILE_PATH)

# carica i messaggi di errore del modulo
easyspid_error_configuration = commonlib.configure(ESPID_ERRORS_FILE_PATH)

# istanzia le sezioni del fle di configurazione nel file globalsObj
globalsObj.easyspid_DbMaster_conf = dict(easyspid_file_configuration.items('DbMaster'))
globalsObj.easyspid_DbSlave_conf = dict(easyspid_file_configuration.items('DbSlave'))
globalsObj.easyspid_postFormPath = easyspid_file_configuration.get('AuthnRequest','postFormPath')
globalsObj.easyspid_responseFormPath = easyspid_file_configuration.get('Response','responseFormPath')

# istanzia tutte le sezioni degli errori nel file globalsObj
for i, val in enumerate(easyspid_error_configuration.sections()):
    if val != 'conf':
        globalsObj.errors_configuration.add_section(val)
        tempDict = dict(easyspid_error_configuration.items(val))
        for j, val2 in enumerate(tempDict.keys()):
            globalsObj.errors_configuration.set(val, val2, tempDict[val2])

## crea il pool per questo modulo
try:
    globalsObj.DbConnections
except Exception as error:
    globalsObj.DbConnections = dict()

# connect to DB master
dsnMaster = "host=" + easyspid_file_configuration.get('DbMaster','host') + \
    " port=" + easyspid_file_configuration.get('DbMaster','port') + \
    " dbname=" + easyspid_file_configuration.get('DbMaster','dbname')+ \
    " user=" + easyspid_file_configuration.get('DbMaster','user') + \
    " password=" + easyspid_file_configuration.get('DbMaster','password') + \
    " application_name=" + easyspid_file_configuration.get('DbMaster','application_name')

globalsObj.DbConnections['samlMasterdsn'] = dsnMaster

# connect to DB slave
dsnSlave = "host=" + easyspid_file_configuration.get('DbSlave','host') + \
    " port=" + easyspid_file_configuration.get('DbSlave','port') + \
    " dbname=" + easyspid_file_configuration.get('DbSlave','dbname')+ \
    " user=" + easyspid_file_configuration.get('DbSlave','user') + \
    " password=" + easyspid_file_configuration.get('DbSlave','password') + \
    " application_name=" + easyspid_file_configuration.get('DbSlave','application_name')

globalsObj.DbConnections['samlSlavedsn'] = dsnSlave

globalsObj.DbConnections['samlDbPollMaster'] = {'max_conn': easyspid_file_configuration.getint('dbpool','max_conn'),
                                                'min_conn': easyspid_file_configuration.getint('dbpool','min_conn'),
                                                'dsn': dsnMaster}

globalsObj.DbConnections['samlDbPollSlave'] = {'max_conn': easyspid_file_configuration.getint('dbpool','max_conn'),
                                               'min_conn': easyspid_file_configuration.getint('dbpool','min_conn'),
                                                'dsn': dsnSlave}

# inizializza dB object
globalsObj.DbConnections['samlDb'] = easyspid.lib.database.Database()
globalsObj.DbConnections['samlDb'].prepare_stmts()

# set some settings
globalsObj.easyspidSettings = dict()
globalsObj.easyspidSettings['idp'] = {
    "entityId": "https://app.onelogin.com/saml/metadata/<onelogin_connector_id>",
    "singleSignOnService": {
      "url": "https://app.onelogin.com/trust/saml2/http-post/sso/<onelogin_connector_id>",
      "binding": "urn:oasis:names:tc:SAML:2.0:bindings:HTTP-Redirect"
    },
    "singleLogoutService": {
      "url": "https://app.onelogin.com/trust/saml2/http-redirect/slo/<onelogin_connector_id>",
      "binding": "urn:oasis:names:tc:SAML:2.0:bindings:HTTP-Redirect"
    },
    "x509cert": "<onelogin_connector_cert>"
  }


def spSettings(cod_sp, cod_idp = None, binding= OneLogin_Saml2_Constants.BINDING_HTTP_REDIRECT, close = True):
    result = {'error':0, 'result': None}

    # acquisisci una connessione dal pool
    #if conn is None:
    #    conn = easyspid.lib.database.Database(globalsObj.DbConnections['samlDbPollSlave']['pool'])
    #sp_settings = conn.get_sp_settings(cod_sp, close)

    dbobj = globalsObj.DbConnections['samlDb']
    sp_settings = dbobj.makeQuery("EXECUTE get_sp_settings(%s)",
                        [cod_sp],type = dbobj.stmts['get_providers']['pool'], close=close)

    if sp_settings['error'] == 0 and sp_settings['result'] != None:
        # genera risposta tutto ok
        sp_settings['result']['settings']['idp'] = globalsObj.easyspidSettings['idp']
        sp_settings['result']['settings']['sp']['x509cert'] = sp_settings['result']['public_key']
        sp_settings['result']['settings']['sp']['privateKey'] = sp_settings['result']['private_key']
        sp_settings['result']['settings']['sp']['x509cert_fingerprint'] = sp_settings['result']['fingerprint']
        sp_settings['result']['settings']['sp']['x509cert_fingerprintalg'] = sp_settings['result']['fingerprintalg']
        sp_settings['result']['settings']['security'] = sp_settings['result']['advanced_settings']['security']
        sp_settings['result']['settings']['contactPerson'] = sp_settings['result']['advanced_settings']['contactPerson']
        sp_settings['result']['settings']['organization'] = sp_settings['result']['advanced_settings']['organization']

        if cod_idp != None:
            #idp_metadata = globalsObj.DbConnections['samlSlave'].get_prvd_metadta(cod_idp)
            #idp_metadata = conn.get_prvd_metadta(cod_idp, close)

            idp_metadata = dbobj.makeQuery("EXECUTE get_prvd_metadta(%s)",
                        [cod_idp],type = dbobj.stmts['get_providers']['pool'], close=close)

            if idp_metadata['error'] == 0 and idp_metadata['result'] != None:

                metadata = idp_metadata['result']['xml']
                idp_data = OneLogin_Saml2_IdPMetadataParser.parse(metadata, required_sso_binding= binding, required_slo_binding=binding)
                idp_settings = idp_data['idp']

                if 'entityId' in idp_settings:
                    sp_settings['result']['settings']['idp']['entityId'] = idp_settings['entityId']
                if 'singleLogoutService' in idp_settings:
                    sp_settings['result']['settings']['idp']['singleLogoutService'] = idp_settings['singleLogoutService']
                if 'singleSignOnService' in idp_settings:
                    sp_settings['result']['settings']['idp']['singleSignOnService'] = idp_settings['singleSignOnService']
                if 'x509cert' in idp_settings:
                    sp_settings['result']['settings']['idp']['x509cert'] = idp_settings['x509cert']

                sp_settings['result']['settings']['idp']['x509cert_fingerprint'] = idp_metadata['result']['fingerprint']
                sp_settings['result']['settings']['idp']['x509cert_fingerprintalg'] = idp_metadata['result']['fingerprintalg']
                sp_settings['result']['settings']['idp']['metadata'] = metadata

                result['result'] = sp_settings['result']['settings']
                return result

            elif idp_metadata['error'] > 0:
                result['error'] = 1
                response_obj = ResponseObj(debugMessage=idp_metadata['result'].pgerror, httpcode=500,
                            devMessage=("PostgreSQL error code: %s" % idp_metadata['result'].pgcode))
                response_obj.setError('easyspid105')
                result['result'] = response_obj

            else:
                result['error'] = idp_metadata['error']
                result['result'] = idp_metadata['result']
        else:
            result['result'] = sp_settings['result']['settings']
            return result

    elif sp_settings['error'] > 0:
        result['error'] = 1
        response_obj = ResponseObj(debugMessage=sp_settings['result'].pgerror, httpcode=500,
                    devMessage=("PostgreSQL error code: %s" % sp_settings['result'].pgcode))
        response_obj.setError('easyspid105')
        result['result'] = response_obj

    else:
        result['error'] = sp_settings['error']
        result['result'] = sp_settings['result']

    return result

def timeValidateCert(cert, date = datetime.datetime.now()):
    try:
        certByte = cert.encode(encoding='UTF-8')

    except AttributeError:
        certByte = cert

    certDecode = x509.load_pem_x509_certificate(certByte, default_backend())

    if certDecode.not_valid_before <= date and certDecode.not_valid_after >= date:
        return True

    else:
        return False

def get_metadata_allowed_cert(xmlData):
        """
        Get x509 cert of a saml metadata

        :param xmlData: The element we should get certificate of
        :type: string | Document

        :param assertion: The assertion name we should get certificate of
        :type: string | Document

        """
        if xmlData is None or xmlData == '':
            raise Exception('Empty string supplied as input')

        xpath = ".//*[local-name()='KeyDescriptor'][@use='signing']//*[local-name()='X509Certificate']"

        parsedXml = etree.fromstring(xmlData)
        cert_nodes = parsedXml.xpath(xpath)

        if len(cert_nodes) > 0:
            x509_cert = cert_nodes[0].text.replace('\x0D', '')
            x509_cert = x509_cert.replace('\r', '')
            x509_cert = x509_cert.replace('\n', '')
            tmp = ("-----BEGIN CERTIFICATE-----\n%s\n-----END CERTIFICATE-----" % x509_cert)
            return  tmp

        else:
            raise Exception('Could not find any singning certificate')

def get_signature_cert(xmlData):
        """
        Get x509 cert of a signature node

        :param xmlData: The element we should validate
        :type: string | Document

        """
        if xmlData is None or xmlData == '':
            raise Exception('Empty string supplied as input')

        parsedXml = etree.fromstring(xmlData)
        cert_nodes = parsedXml.xpath(".//*[local-name()='Signature']//*[local-name()='X509Certificate']")

        if len(cert_nodes) > 0:
            x509_cert = cert_nodes[0].text.replace('\x0D', '')
            x509_cert = x509_cert.replace('\r', '')
            x509_cert = x509_cert.replace('\n', '')
            tmp = ("-----BEGIN CERTIFICATE-----\n%s\n-----END CERTIFICATE-----" % x509_cert)
            return tmp

        else:
            raise Exception('Could not validate certificate: No Signatire node found.')

def calcCertFingerprint(x509cert, alg):
    result = {'error':0, 'result': None}

    try:
        lines = x509cert.split('\n')
        data = ''

        for line in lines:
            # Remove '\r' from end of line if present.
            line = line.rstrip()
            if line == '-----BEGIN CERTIFICATE-----':
                # Delete junk from before the certificate.
                data = ''
            elif line == '-----END CERTIFICATE-----':
                # Ignore data after the certificate.
                break
            elif line == '-----BEGIN PUBLIC KEY-----' or line == '-----BEGIN RSA PRIVATE KEY-----':
                # This isn't an X509 certificate.
                return  ""
            else:
                # Append the current line to the certificate data.
                data += line

        decoded_data = base64.b64decode(str(data))

        if alg == 'sha512':
            fingerprint = sha512(decoded_data)
        elif alg == 'sha384':
            fingerprint = sha384(decoded_data)
        elif alg == 'sha256':
            fingerprint = sha256(decoded_data)
        elif alg == None or alg == 'sha1':
            fingerprint = sha1(decoded_data)
        else:
            result = {'error':1, 'result': 'algorithm not faound'}
            return result

        result = {'error':0, 'result': fingerprint.hexdigest().lower()}
        return result

    except BaseException as error:
        result = {'error':2, 'result': error}
        return result
