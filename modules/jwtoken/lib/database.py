import globalsObj
import psycopg2.extras
import psycopg2.pool
import logging

class Database(object):
    
    def __init__(self, **kwds):

        self.pool1 = psycopg2.pool.SimpleConnectionPool(globalsObj.DbConnections['jwtDbPollMaster']['min_conn'],
                                    globalsObj.DbConnections['jwtDbPollMaster']['max_conn'],
                                    globalsObj.DbConnections['jwtDbPollMaster']['dsn'])

        self.pool2 = psycopg2.pool.SimpleConnectionPool(globalsObj.DbConnections['jwtDbPollSlave']['min_conn'],
                                    globalsObj.DbConnections['jwtDbPollSlave']['max_conn'],
                                    globalsObj.DbConnections['jwtDbPollSlave']['dsn'])

        # define query to prepare
        self.stmts = dict()
        self.stmts['get_token_by_cod'] = {'sql':"PREPARE get_token_by_cod (text) AS " \
                    "SELECT * FROM jwt.token WHERE cod_token = $1", 'pool':'slave'}

        self.stmts['create_token_by_type'] = {'sql':"PREPARE create_token_by_type (text) AS " \
                        "SELECT lib.create_token_byType($1) as cod_token", 'pool':'master'}

        self.stmts['verify_token'] = {'sql':"PREPARE verify_token (text) AS " \
                        "SELECT lib.verify_token_bycod((SELECT t1.cod_token FROM jwt.token as t1"
                        " WHERE t1.token = $1))", 'pool':'slave'}

        self.stmts['log_request'] = {'sql':"PREPARE log_request (text, text, jsonb, inet) AS " \
                        "INSERT INTO log.requests (http_verb, url, request, client) VALUES ($1, $2, $3, $4)",
                        'pool':'master'}

        self.stmts['log_response'] = {'sql':"PREPARE log_response (text, text, jsonb, inet) AS " \
                        "INSERT INTO log.responses (http_code, url_origin, response, client) VALUES ($1, $2, $3, $4)",
                        'pool':'master'}

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

    # def getTokenByCod(self, cod, close = True):
    #     cur = self.conn.cursor(cursor_factory=psycopg2.extras.DictCursor)
    #
    #     try:
    #         cur.execute("SELECT * FROM jwt.token WHERE cod_token = %s", [cod])
    #         result = cur.fetchone()
    #         self.conn.commit()
    #
    #         if close:
    #             self.close()
    #
    #         return {'error':0, 'result':result}
    #
    #     except psycopg2.InternalError as error:
    #         self.conn.commit()
    #         self.close()
    #         return {'error':1, 'result':error}
    #
    #     except psycopg2.Error as error:
    #         self.conn.commit()
    #         self.close()
    #         return {'error':2, 'result':error}
    #
    # def createTokenByType(self, tokenType, close = True):
    #     cur = self.conn.cursor(cursor_factory=psycopg2.extras.DictCursor)
    #
    #     try:
    #         cur.execute("SELECT lib.create_token_byType(%s) as cod_token", [tokenType])
    #         result = cur.fetchone()
    #         self.conn.commit()
    #
    #         if close:
    #             self.close()
    #
    #         result = self.getTokenByCod(result[0])
    #
    #         return result
    #
    #     except psycopg2.InternalError as error:
    #         self.conn.commit()
    #         self.close()
    #         return {'error':1, 'result':error}
    #
    #     except psycopg2.Error as error:
    #         self.conn.commit()
    #         self.close()
    #         return {'error':2, 'result':error}
    #
    # def verifyToken(self, token, close = True):
    #     cur = self.conn.cursor(cursor_factory=psycopg2.extras.DictCursor)
    #
    #     try:
    #         cur.execute("SELECT lib.verify_token_bycod((SELECT t1.cod_token FROM jwt.token as t1"
    #                     " WHERE t1.token = %s))", [token])
    #         result = cur.fetchone()
    #         self.conn.commit()
    #
    #         if close:
    #             self.close()
    #
    #         return {'error':0, 'result':result}
    #
    #     except psycopg2.InternalError as error:
    #         self.conn.commit()
    #         self.close()
    #         return {'error':1, 'result':error}
    #
    #     except psycopg2.Error as error:
    #         self.conn.commit()
    #         self.close()
    #         return {'error':2, 'result':error}

    def makeQuery(self, sql, sqlargs, type = 'master', close = True, conn = None, fetch=True):
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

   
        