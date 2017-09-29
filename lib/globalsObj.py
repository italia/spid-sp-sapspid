__author__ = 'franco'

# Default config file
CONFIG_FILE_PATH = "conf/server.ini"
CONFIG_LOGGING_PATH = "conf/logging.ini"

jsonReqSchema = {
      "type": "object",
      "required": [
        "id",
        "apiVersion",
        "request"
      ],
      "properties": {
        "id": {
          "type": ["string","null"],
          "minLength": 1
        },
        "apiVersion": {
          "type": "string",
          "minLength": 1
        },
        "request": {
          "type": "object",
          "additionalProperties": True
        }
      },
      "additionalProperties": False
    }
