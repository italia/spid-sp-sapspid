import globalsObj
import commonlib as commonlib
import jwtoken.lib.database

JWT_ERRORS_FILE_PATH = "modules/jwtoken/conf/errors.ini"
JWT_CONFIG_FILE_PATH = "modules/jwtoken/conf/jwtoken.ini"

# carica le configurazioni globali e locali del modulo
jwtoken_file_configuration = commonlib.configure(JWT_CONFIG_FILE_PATH)
if globalsObj.configuration.has_option('jwtoken','conf'):
    jwtoken_file_configuration = commonlib.configure(globalsObj.configuration.get('jwtoken','conf'),jwtoken_file_configuration)

# try:
#     jwtoken_file_configuration = commonlib.configure(JWT_CONFIG_FILE_PATH, globalsObj.configuration.get('jwtoken','conf'))
# except BaseException as error:
#     jwtoken_file_configuration = commonlib.configure(JWT_CONFIG_FILE_PATH)

# carica i messaggi di errore del modulo
jwtoken_error_configuration = commonlib.configure(JWT_ERRORS_FILE_PATH)

# istanzia le sezioni del fle di configurazione nel file globalsObj
globalsObj.jwtoken_DbMaster_conf = dict(jwtoken_file_configuration.items('DbMaster'))
globalsObj.jwtoken_DbSlave_conf = dict(jwtoken_file_configuration.items('DbSlave'))

# istanzia tutte le sezioni degli errori nel file globalsObj
for i, val in enumerate(jwtoken_error_configuration.sections()):
    if val != 'conf':
        globalsObj.errors_configuration.add_section(val)
        tempDict = dict(jwtoken_error_configuration.items(val))
        for j, val2 in enumerate(tempDict.keys()):
            globalsObj.errors_configuration.set(val, val2, tempDict[val2])

## crea le conenssini con il DB
try:
    globalsObj.DbConnections
except Exception as error:
    globalsObj.DbConnections = dict()

# connect to DB master
dsnMaster = "host=" + jwtoken_file_configuration.get('DbMaster','host') + \
    " port=" + jwtoken_file_configuration.get('DbMaster','port') + \
    " dbname=" + jwtoken_file_configuration.get('DbMaster','dbname')+ \
    " user=" + jwtoken_file_configuration.get('DbMaster','user') + \
    " password=" + jwtoken_file_configuration.get('DbMaster','password') + \
    " application_name=" + jwtoken_file_configuration.get('DbMaster','application_name')

globalsObj.DbConnections['jwtMasterdsn'] = dsnMaster

# connect to DB slave
dsnSlave = "host=" + jwtoken_file_configuration.get('DbSlave','host') + \
    " port=" + jwtoken_file_configuration.get('DbSlave','port') + \
    " dbname=" + jwtoken_file_configuration.get('DbSlave','dbname')+ \
    " user=" + jwtoken_file_configuration.get('DbSlave','user') + \
    " password=" + jwtoken_file_configuration.get('DbSlave','password') + \
    " application_name=" + jwtoken_file_configuration.get('DbSlave','application_name')

globalsObj.DbConnections['jwtSlavedsn'] = dsnSlave

globalsObj.DbConnections['jwtDbPollMaster'] = {'max_conn': jwtoken_file_configuration.getint('dbpool','max_conn'),
                                    'min_conn': jwtoken_file_configuration.getint('dbpool','min_conn'),
                                      'dsn': dsnMaster}

globalsObj.DbConnections['jwtDbPollSlave'] = {'max_conn': jwtoken_file_configuration.getint('dbpool','max_conn'),
                                    'min_conn': jwtoken_file_configuration.getint('dbpool','min_conn'),
                                      'dsn': dsnSlave}

# inizializza dB object
globalsObj.DbConnections['jwtDb'] = jwtoken.lib.database.Database()
globalsObj.DbConnections['jwtDb'].prepare_stmts()
