import configparser
import os
import signal
import logging
import argparse
import re

""" read config file """
def configure(default_file, configParser = None):

    Logger = logging.getLogger(__name__)
    if configParser is None:
        file_parser = configparser.ConfigParser(allow_no_value=True)
        #file_parser.add_section('conf')
    else:
        file_parser = configParser

    # try load config file
    try:
        file_parser.read_file(open(default_file))
        #file_parser.set('conf','default', default_file)
        Logger.warning("Read config file "+ default_file)
    except configparser.Error:
        Logger.error('Impossible read ' + default_file + '. Check path and permissions')
        run = 0

    # try to load the local config file
    # if(local_file != None):
    #     try:
    #         file_parser.read_file(open(local_file))
    #         file_parser.set('conf','local', local_file)
    #         Logger.warning("Read config files "+ file_parser.get('conf','local') + " and " + file_parser.get('conf','default'))
    #     except configparser.Error:
    #         Logger.warning('Impossible read ' + local_file + '. Check path and permissions')
    # else:
    #     file_parser.set('conf','local', 'none')

    return file_parser

""" write pid file """
def writePid(file):
    fileHandler = open(file,"w")
    pid = os.getpid()
    fileHandler.write(str(pid)+"\n")
    fileHandler.close()

""" send kill signal to a process with pid """
def kill(pid):
    try:
        os.kill(pid, signal.SIGKILL)
    except OSError:
        pass

""" send term signal to a process with pid """
def term(pid):
    try:
        os.kill(pid, signal.SIGTERM)
    except OSError:
        pass

def commandLine(configFile):
    cmd_line_parser = argparse.ArgumentParser(description = 'Tornado Web Server')
    cmd_line_parser.add_argument("-c", "--conf", dest="filename",
        metavar="FILE", help="server configuration file. Default: "+configFile)
    #cmd_line_parser.add_argument("-w", "--wspath", dest="wsfilename",
    # #metavar="FILE", help="web services path configuration file. Default: "+CONFIG_WSPATH_PATH)
    options = cmd_line_parser.parse_args()
    return options

def loggingfileConfig2dictConfig(fileConfig, deafultDict = None, disable_existing_loggers=True, incremental = False):

    if deafultDict is None:
        dictConfig = dict()
        dictConfig['version'] = 1
        dictConfig['disable_existing_loggers'] = disable_existing_loggers
        dictConfig['incremental'] = incremental
        dictConfig['formatters'] = dict()
        dictConfig['handlers'] = dict()
        dictConfig['loggers'] = dict()
        dictConfig['root'] = dict()
    else:
        dictConfig = deafultDict
        dictConfig['disable_existing_loggers'] = disable_existing_loggers
        dictConfig['incremental'] = incremental

    file_parser = configparser.RawConfigParser(allow_no_value=True)
    file_parser.read_file(open(fileConfig))

    # formatters
    if file_parser.has_section('formatters'):
        formattersName = ((file_parser.get('formatters', 'keys')).strip()).split(",")
        for key in formattersName:
            dictConfig['formatters'][key] = dict()
            formatter = file_parser.options('formatter_'+key)
            for key2 in formatter:
                dictConfig['formatters'][key][key2] = file_parser.get('formatter_'+key, key2)

    # handlers
    if file_parser.has_section('handlers'):
        handlersName = ((file_parser.get('handlers', 'keys')).strip()).split(",")
        for key in handlersName:
            dictConfig['handlers'][key] = dict()
            handler = file_parser.options('handler_'+key)
            for key2 in handler:
                if key2 == 'address':
                    dictConfig['handlers'][key][key2] = eval(file_parser.get('handler_'+key, key2))
                else:
                    dictConfig['handlers'][key][key2] = file_parser.get('handler_'+key, key2)

    # loggers
    if file_parser.has_section('loggers'):
        loggersName = ((file_parser.get('loggers', 'keys')).strip()).split(",")
        for key in loggersName:
            if key != 'root':
                dictConfig['loggers'][key] = dict()
                logger = file_parser.options('logger_'+key)
                for key2 in logger:
                    if key2 == 'handlers':
                        dictConfig['loggers'][key][key2] = ((file_parser.get('logger_'+key, key2)).strip()).split(",")

                    else:
                        dictConfig['loggers'][key][key2] = file_parser.get('logger_'+key, key2)

            elif key == 'root':
                logger = file_parser.options('logger_'+key)
                for key2 in logger:
                    if key2 == 'handlers':
                        dictConfig['root'][key2] = ((file_parser.get('logger_'+key, key2)).strip()).split(",")

                    else:
                        dictConfig['root'][key2] = file_parser.get('logger_'+key, key2)

    return dictConfig

'''
Returns instance of ConfigParser or RawConfigParser
newIni and oldIni can be file or ConfigParser instances
'''
def incrementalIniFile(newIni, oldIni = None, rawParser = True, separator = ','):

    if rawParser:
        outConfig = configparser.RawConfigParser()
        newConfig = configparser.RawConfigParser()
    else:
        outConfig = configparser.ConfigParser()
        newConfig = configparser.ConfigParser()
    try:
        newConfig.read_file(open(newIni))
    except:
        newConfig = newIni

    if oldIni is not None:
        try:
            outConfig.read_file(open(oldIni))
        except:
            outConfig = oldIni

    # process newIni
    sections = newConfig.sections()
    for section in sections:
        options = newConfig.options(section)

        if not outConfig.has_section(section):
            outConfig.add_section(section)

        for option in options:
            #if outConfig.has_option(section, option) and (option == 'keys' or option =='handlers') \
            #    and not re.search(newConfig.get(section, option), outConfig.get(section, option)):
            if outConfig.has_option(section, option) and option == 'keys' \
                and not re.search(newConfig.get(section, option), outConfig.get(section, option)):

                newValue = outConfig.get(section, option) + separator + newConfig.get(section, option)
            else:
                newValue = newConfig.get(section, option)

            outConfig.set(section, option, newValue)

    return outConfig