__author__ = 'ggiustiniani'


class ApplicationException(Exception):

    def __init__(self, code, message=''):
        super(Exception, self).__init__(message)

        self.code = code
        pass


class ErrorConstans:

    ERROR_CODE_XML_CONTENT_NOT_VALID = '104'

