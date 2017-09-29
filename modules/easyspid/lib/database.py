import psycopg2.extras
import psycopg2.pool
import globalsObj
import logging

class Database(object):
    
    def __init__(self, **kwds):

        self.pool1 = psycopg2.pool.SimpleConnectionPool(globalsObj.DbConnections['samlDbPollMaster']['min_conn'],
                                    globalsObj.DbConnections['samlDbPollMaster']['max_conn'],
                                    globalsObj.DbConnections['samlDbPollMaster']['dsn'])

        self.pool2 = psycopg2.pool.SimpleConnectionPool(globalsObj.DbConnections['samlDbPollSlave']['min_conn'],
                                    globalsObj.DbConnections['samlDbPollSlave']['max_conn'],
                                    globalsObj.DbConnections['samlDbPollSlave']['dsn'])

        # define query to prepare
        self.stmts = dict()
        self.stmts['get_prvd_metadta'] = {'sql':"PREPARE get_prvd_metadta (text) AS " \
                    "SELECT t1.*, t2.public_key, t2.private_key, t2.fingerprint, t2.fingerprintalg  FROM saml.metadata as t1 " \
                    "LEFT JOIN saml.signatures as t2 on t2.cod_provider = t1.cod_provider " \
                    "where t1.cod_provider = $1 and t1.active = TRUE LIMIT 1", 'pool':'slave'}

        self.stmts['get_sp_settings'] = {'sql':"PREPARE get_sp_settings (text) AS " \
                    "SELECT t1.*, t2.public_key, t2.private_key, t2.fingerprint, t2.fingerprintalg  FROM saml.settings as t1 " \
                    "LEFT JOIN saml.signatures as t2 on t2.cod_provider = t1.cod_provider " \
                    "where t1.cod_provider = $1 and t1.active = TRUE LIMIT 1", 'pool':'slave'}

        self.stmts['get_providers'] = {'sql':"PREPARE get_providers (bool) AS " \
                    "SELECT t1.* FROM saml.providers as t1 where t1.active = $1 ORDER BY name ASC", 'pool':'slave'}

        self.stmts['get_provider_byentityid'] = {'sql':"PREPARE get_provider_byentityid (bool, text) AS " \
                "SELECT t1.* FROM saml.metadata as t1 where t1.active = $1 " \
                "and cast(xpath('/md1:EntityDescriptor/@entityID', \"xml\", ARRAY[ARRAY['md1', 'urn:oasis:names:tc:SAML:2.0:metadata']]) as text) = $2" \
                "ORDER BY cod_provider ASC", 'pool':'slave'}

        self.stmts['write_assertion'] = {'sql':"PREPARE write_assertion (xml, text, text, inet) AS " \
                        "INSERT INTO saml.assertions (assertion, cod_sp, cod_idp, client) VALUES ($1, $2, $3, $4) " \
                        "RETURNING cod_token, \"ID_assertion\"", 'pool':'master'}

        # self.stmts['get_services'] = {'sql':"PREPARE get_services (bool) AS " \
        #                 "SELECT t1.* FROM saml.services as t1 where t1.active = $1 ORDER BY name ASC", 'pool':'slave'}

        self.stmts['get_service'] = {'sql':"PREPARE get_service (bool, text, text) AS " \
                        "SELECT t1.* FROM saml.services as t1 where t1.active = $1 and t1.relay_state = $2 "
                        "and t1.cod_provider = $3", 'pool':'slave'}

        self.stmts['get_idAssertion'] = {'sql':"PREPARE get_idAssertion (text) AS " \
                        "SELECT t1.* FROM saml.view_assertions as t1 where t1.\"ID_assertion\" = $1", 'pool':'slave'}

        self.stmts['chk_idAssertion'] = {'sql':"PREPARE chk_idAssertion (text) AS " \
                        "SELECT t1.* FROM saml.view_assertions as t1 where t1.\"ID_assertion\" = $1", 'pool':'slave'}

        self.stmts['log_request'] = {'sql':"PREPARE log_request (text, text, text, inet) AS " \
                        "INSERT INTO log.requests (http_verb, url, request, client) VALUES ($1, $2, $3, $4)",
                        'pool':'master'}

        self.stmts['log_response'] = {'sql':"PREPARE log_response (text, text, text, inet) AS " \
                        "INSERT INTO log.responses (http_code, url_origin, response, client) VALUES ($1, $2, $3, $4)",
                        'pool':'master'}

        self.stmts['get_signature'] = {'sql':"PREPARE get_signature (text) AS " \
                        "SELECT * FROM saml.signatures WHERE cod_provider = $1",
                        'pool':'slave'}

    # prepare statments for each connection pool
    def prepare_stmts(self):
        for key, value in self.stmts.items():

            if value['pool'] == 'master':
                for conn in self.pool1._pool:
                    self.makeQuery(value['sql'], None, type = value['pool'], close=False, conn=conn)

            elif value['pool'] == 'slave':
                for conn in self.pool2._pool:
                    self.makeQuery(value['sql'], None, type = value['pool'], close=False, conn=conn)

    def get(self, type = 'master'):

        try:
            if type == 'master':
                return self.pool1.getconn()

            elif type == 'slave':
                return self.pool2.getconn()

        except psycopg2.pool.PoolError as error:

            logging.getLogger(__name__).error('%s' % error, exc_info=True)

    def close(self, conn, type = 'master'):

        if type == 'master':
            self.pool1.putconn(conn)
        elif type == 'slave':
            self.pool2.putconn(conn)

    def makeQuery(self, sql, sqlargs, type = 'master', close = True, conn = None, fetch = True):
        result = None

        try:
            if conn is not None:
                cur = conn.cursor(cursor_factory=psycopg2.extras.DictCursor)
            else:
                conn = self.get(type = type)
                cur = conn.cursor(cursor_factory=psycopg2.extras.DictCursor)

            cur.execute(sql, sqlargs)

            if fetch:
                if cur.rowcount == 1:
                    result = cur.fetchone()
                elif cur.rowcount > 1:
                    result = cur.fetchall()

            conn.commit()

            if close:
                self.close(conn, type = type)

            return {'error':0, 'result':result}

        except psycopg2.InternalError as error:
            conn.commit()
            self.close(conn, type = type)
            return {'error':1, 'result':error}

        except psycopg2.Error as error:
            conn.commit()
            self.close(conn, type = type)
            return {'error':2, 'result':error}
   
        