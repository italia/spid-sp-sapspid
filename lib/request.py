#import jsonlib2
import logging
import jsonpickle
import jsonschema
import globalsObj
#import tornado.web

class Request(object):
    """
    La calsse Request prende come argomento una classe, la istanza e lassegna
    all'attributo `targetClass`.
    """
    def __init__(self, targetClass):
        try:
            self.targetClass = targetClass()
        except BaseException as error:
            self.targetClass = None
            logging.getLogger(__name__).error(error)

    """
    Il metodo `reload` ricarica una nuova classe o lista di classi nell'attributo `targetClass`
    """
    def reload(self,targetClass):
        self.__init__(targetClass)

class RequestObjNew(object):
    """
    La classe tarforma un json in una classe python.
    Accetta come unico argomento un json
    Il json deve avere il seguente foramto:
    `{
        "id": null,
         "request": {
         },
        "apiVersion": "0.1" DEPRECATO
    }`
    Il nodo `request` contiente il json che deve essere convertito nella classe Python
    """
    def __init__(self, json):
        self.error = {"message":'', "code": 0}

        # validate request
        try:
            jsonschema.validate(jsonpickle.decode(json), globalsObj.jsonReqSchema)
            self.json = json
            self.jsonRead()

        except jsonschema.ValidationError as error:
            logging.getLogger(__name__).error('Validation error. Json input error')
            self.error = {"message":error.message, "code": 2}

    """
    Il metodo accetta in input la classe target nella quale sara' mappato il json della richiesta.
    La classe popolata con il json e' asseganta all'attributo `targetClass`
    """
    def mapRequest(self, targetClass):
        tmp = Request(targetClass).targetClass
        try:
            for (key, values) in self.request.viewitems():
                tmp.__dict__[key] = values
        except:
            pass

        self.targetClass = tmp

    """
    Legge il json in input e separa i nodi: `request`, 'apiVersion`, 'id`
    """
    def jsonRead(self):
        try:
            #tmp = jsonlib2.read(self.json)
            tmp = jsonpickle.decode(self.json)
            ## trasforma le chiavi del dict jsonobj in formato ASCII
            #tmp = keys_to_str(tmp)
            self.jsonObj = tmp
            self.request =  self.jsonObj['request']
            #self.apiVersion = self.jsonObj['apiVersion']
            self.id = self.jsonObj['id']
            return True

        #except jsonlib2.ReadError as error:
        #    msg = "Error on json decoding %s" % (error)
        #    logging.getLogger(__name__).error(msg)
        #    self.error["message"] = msg
        #    self.error["code"] = 1
        #    return False

        except Exception as error:
            msg = "Error on json decoding %s" % (error)
            self.error["message"] = msg
            self.error["code"] = 1
            logging.getLogger(__name__).error(msg)
            return False

def keys_to_str(dictionary):
  if type(dictionary) is dict:
    return dict([(key.encode('ascii',errors='strict'), keys_to_str(value)) for key, value in dictionary.items()])
  else:
    return dictionary