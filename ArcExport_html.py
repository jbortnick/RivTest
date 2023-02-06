#!/usr/bin/python
#
# ArcExport.py
# Version: 1.00
#

import json
import csv
import sys
import os
import time
import datetime
import urllib3
import requests

class ArcExport:
    ''' Utility to access ARC Exports stream and query'''

    # Authentication information
    auth_server_urlOverride = False
    auth_server_url = ''
    arc_urlOverride = False
    arc_url = ''
    authheaders = {'Content-Type': 'application/x-www-form-urlencoded', }
    # Tenant specific info
    client_headers = {'X-Forwarded-For': '10.26.5.13', 'Authorization': ''}
    client_idOverride = False
    client_id = ''
    client_secretOverride = False
    client_secret = ''

    config_loc = './arcconfig.json'
    output_loc = './response.csv'
    output_html = './response.html'
    print_console = False
    print_csv = False
    print_html = False
    exportGuid = ''
    request_name = ''
    showNull = True

    api_key = ''
    api_key_timeout = 0

    # GET /1.0/rest/1.0/export_profiles/guid/export
    def getExport(self, exportGuid, exportFile, dataExportType):
        incident_list = self.get_export(exportGuid, dataExportType)
        if exportFile == 'stdout':
            #print(json.dumps(incident_list, indent=4, sort_keys=True))
            newlist=[]
            for i in range(len(incident_list)):
                newdict={}
                for k,v in incident_list[i].items():
                    if v != 'null':
                        newdict[k] = v
                    newlist.append(newdict)
            for items in newlist:
                print(json.dumps(items, indent=4, sort_keys=True))
                i+= 1
        else:
            f = open(exportFile, "w")
            f.write(json.dumps(incident_list))
            self.outputHTML(json.dumps(incident_list))
            f.close()
        print('Exported {0} events'.format(len(incident_list)))
        exit(0)

    def get_export(self, exportGuid, dataExportType):
        export_list = []
        arcmap={}
        try:
            with open('arcmap.json') as json_file:
                arcmap = json.load(json_file)
                json_file.close()
        except FileNotFoundError as fe:
                print('arcmap.json not found')
                print('Error: %s' %fe)
                print('use arcmap.py displaynames arcpreamble\n')
        except ValueError as ve:
                print('Error: %s' %ve)


        while True:
            if dataExportType =='stream':
                full_url = self.arc_url + '/rest/1.0/export_profiles/' + exportGuid + '/export_and_ack'
                r = requests.post(url=full_url, headers=self.client_headers, verify=False)
            if dataExportType =='query':
                full_url = self.arc_url + '/rest/1.0/export_profiles/' + exportGuid + '/export'
                r = requests.get(url=full_url, headers=self.client_headers, verify=False)
            jsonText = json.loads(r.text)
            #print(json.dumps(jsonText, indent=4, sort_keys=True))
            if r.status_code == 200:
                headerField = []
                items = {}
                exportdata = []
                if jsonText['total_hits'] == 0:
                    print('No data found')
                    exit(0)
                if (len(jsonText["data"])) !=0:
                    print('just pulled ' + str(len(jsonText["data"])) + ' records')
                if len(jsonText["data"]) == 0:
                    break
                else:
                    for field in jsonText['fields']:
                        try:
                            headerField.append(arcmap[field['name']])
                        except KeyError:
                            headerField.append(field['display_name'])
                            print('could not map ' + field['name'])
                    for data in jsonText['data']:
                        entryLine = {}
                        headerPosition = 0
                        for dataValue in data:
                            if not dataValue:
                                entryLine[headerField[headerPosition]] = "null"
                            else:
                                entryLine[headerField[headerPosition]] = dataValue
                            headerPosition += 1
                        exportdata.append(entryLine)
                    for items in exportdata:
                        item_list = []
                        try:
                            if items.get('Server Process Time', None) != "null":
                                items['Server Process Time'] = \
                                (datetime.datetime.utcfromtimestamp(items['Server Process Time']/1000).strftime("%Y-%m-%d %H:%M:%S"))
                        except:
                            pass
                        export_list.append(items)
                    if (len(jsonText["data"]) < 10000):
                        break
            if r.status_code != 200:
                print(str(r.reason) + ' code=' + str(r.status_code) + ' access to ARC - check your arc_url and port')
        return export_list

    # GET /1.0/rest/1.0/export_profiles/guid/export
    def pollExport(self, exportGuid, dataExportType, Poll):

        while True:
            print("Polling")
            incident_list = self.get_export(exportGuid, dataExportType)
            newlist=[]
            for i in range(len(incident_list)):
                newdict={}
                for k,v in incident_list[i].items():
                    if v != 'null':
                        newdict[k] = v
                    newlist.append(newdict)
            for items in newlist:
                print(json.dumps(items, indent=4, sort_keys=True))
                i+= 1
            time.sleep(Poll)
        exit(0)

    def validateApiToken(self):
        if self.api_key == '':
            return False
        payload = {
            'client_id': self.client_id,
            'client_secret': self.client_secret,
            'grant_type': 'urn:pingidentity.com:oauth2:grant_type:validate_bearer',
            'token': self.api_key
        }
        api_key_response = requests.post(url=self.auth_server_url+'/as/introspect.oauth2',
                                         headers=self.authheaders, data=payload, verify=False)
        response_json = api_key_response.json()
        if response_json['active']:
            return True
        return False

    def requestApiToken(self):
        if not self.validateApiToken():
            payload = {
                'client_id': self.client_id,
                'client_secret': self.client_secret,
                'grant_type': 'client_credentials',
                'scope': 'client'
            }

            api_key_response = requests.post(url=self.auth_server_url+'/as/token.oauth2',
                                             headers=self.authheaders, data=payload, verify=False)
            response_json = api_key_response.json()

            if api_key_response.status_code == 200:
                self.api_key = response_json['access_token']
                self.client_headers['Authorization'] = 'Bearer ' + self.api_key
                self.saveApiTokenToConfig(self.api_key)
            else:
                print('Request: ' + response_json.text)
                exit(1)
        else:
            self.client_headers['Authorization'] = 'Bearer ' + self.api_key
            # print('API key still active')

    def loadFromConfig(self, fileLoc):
        # load arc information from config file at location
        config = {}
        if self.fileExists(fileLoc):
            with open(fileLoc, 'r') as configJson:
                config = json.load(configJson)
                if not self.auth_server_urlOverride:
                    self.auth_server_url = config['auth_url']
                if not self.arc_urlOverride:
                    self.arc_url = config['arc_url']
                if not self.client_idOverride:
                    self.client_id = config['client_id']
                if not self.client_secretOverride:
                    self.client_secret = config['client_secret']
                if config.get('api_key', 'null') != 'null':
                    self.api_key = config['api_key']
            configJson.close()
        else:
            print('Config file does not exist')
            exit(1)
        return config

    def saveApiTokenToConfig(self, key):
        config = {'auth_url': self.auth_server_url, 'arc_url': self.arc_url, 'client_id': self.client_id,
                  'client_secret': self.client_secret, 'api_key': key}

        with open(self.config_loc, mode='w') as outputJSON:
            json.dump(config, outputJSON)
        outputJSON.close()

    def outputResponse(self, response):
        if self.print_console:
            print('html3')
            print(json.dumps(response, sort_keys=True, indent=4))
        if self.print_csv:
            print('html4')
            self.outputCSV(response)
        if self.print_html:
            print('html5')
            self.outputHTML(response)

    def outputHTML(self,incident_list):

        print('HTML Created')

        with open('response.html', mode='w') as outputHTML:
            title_row = []
            firstEntry = {}
            singleEntry = False

            # Determine if writing a single entry, or multiple entries
            # List = Multiple entry response
            # Dictionary = Single entry response
            if type(response) == list:
                firstEntry = response[0]
                singleEntry = False
            if type(response) == dict:
                firstEntry = response
                singleEntry = True
            try:
                for k in firstEntry:
                    title_row.append(k)
            except Exception:
                print('Entry title not found: ' + str(title_row))
            csvWriter.writerow(title_row)

            try:
                # Single Entry, Dictionary
                if singleEntry:
                    next_row = []
                    for key in title_row:
                        print(key)
                        if response.get(key, 'null') != 'null':
                            if type(response[key]) == list:
                                next_row.append(str(response[key]))
                            else:
                                next_row.append(response[key])
                        else:
                            next_row.append('')
                    csvWriter.writerow(next_row)
                # Multiple Entries, List of Dictionaries
                else:
                    for entry in response:
                        next_row = []
                        for key in title_row:
                            next_row.append(entry[key])
                        csvWriter.writerow(next_row)

                print('Successfully saved to HTML')
            except Exception:
                print('Entry value not found: ' + key)
        outputHTML.close()


    def outputCSV(self, response):
        with open('response.csv', mode='w') as outputCSV:
            csvWriter = csv.writer(outputCSV, delimiter=',', quotechar='"', quoting=csv.QUOTE_MINIMAL)
            title_row = []
            firstEntry = {}
            singleEntry = False

            # Determine if writing a single entry, or multiple entries
            # List = Multiple entry response
            # Dictionary = Single entry response
            if type(response) == list:
                firstEntry = response[0]
                singleEntry = False
            if type(response) == dict:
                firstEntry = response
                singleEntry = True

            try:
                for k in firstEntry:
                    title_row.append(k)
            except Exception:
                print('Entry title not found: ' + str(title_row))
            csvWriter.writerow(title_row)

            try:
                # Single Entry, Dictionary
                if singleEntry:
                    next_row = []
                    for key in title_row:
                        print(key)
                        if response.get(key, 'null') != 'null':
                            if type(response[key]) == list:
                                next_row.append(str(response[key]))
                            else:
                                next_row.append(response[key])
                        else:
                            next_row.append('')
                    csvWriter.writerow(next_row)
                # Multiple Entries, List of Dictionaries
                else:
                    for entry in response:
                        next_row = []
                        for key in title_row:
                            next_row.append(entry[key])
                        csvWriter.writerow(next_row)

                print('Successfully saved to CSV')
            except Exception:
                print('Entry value not found: ' + key)
        outputCSV.close()

    def fileExists(self, fileLoc):
        # Check if a file exists and readable
        if os.path.exists(fileLoc) and os.access(fileLoc, os.R_OK):
            return True
        else:
            return False

    def main(self):
        urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
        args = sys.argv
        # PRINT INPUT
        for itr in range(len(args)):
            # print(str(itr) + ': ' + str(args[itr]))
            if (args[itr] == '--c') or (args[itr] == '--config'):
                if (itr + 1) < len(args):
                    self.configLoc = args[itr + 1]
                    itr += 1
                else:
                    print('Missing config file argument')
                    exit(1)

            if args[itr] == '--auth_url':
                if (itr + 1) < len(args):
                    self.auth_server_url = args[itr + 1]
                    self.auth_server_urlOverride = True
                    itr += 1
                else:
                    print('Missing authenication server url')
                    exit(1)

            if args[itr] == '--arc_url':
                if (itr + 1) < len(args):
                    self.arcrURL = args[itr + 1]
                    self.arc_urlOverride = True
                    itr += 1
                else:
                    print('Missing arc url')
                    exit(1)

            if (args[itr] == '--id') or (args[itr] == '--client_id'):
                if (itr + 1) < len(args):
                    self.client_id = args[itr + 1]
                    self.client_idOverride = True
                    itr += 1
                else:
                    print('Missing client_id')
                    exit(1)

            if (args[itr] == '--s') or (args[itr] == '--client_secret'):
                if (itr + 1) < len(args):
                    self.client_secret = args[itr + 1]
                    self.client_secretOverride = True
                    itr += 1
                else:
                    print('Missing client_secret')
                    exit(1)

            if (args[itr] == '--csv') or (args[itr] == '--output_csv'):
                if (itr + 1) < len(args):
                    self.print_csv = True
                    self.output_loc = args[itr + 1]
                    itr += 1
                else:
                    print('Missing output file')
                    exit(1)

            if (args[itr] == '--html') or (args[itr] == '--output_html'):
                if (itr + 1) < len(args):
                    print('HTML')
                    self.print_html = True
                    print(self.print_html)
                    self.output_html = args[itr + 1]

                    itr += 1
                    # outputHTML(self,incident_list)

                else:
                    print('Missing output file')
                    exit(1)


            # Print to console
            if (args[itr] == '--v') or (args[itr] == '--verbose'):
                self.print_console = True
                # TODO: change print_console to verbose, lock prints behind verbose

            if (args[itr] == '--ge') or (args[itr] == '--get_export'):
                if itr == (len(args) - 4):
                    exportGuid = args[itr + 1]
                    dataExportType = args[itr + 2]
                    exportFile = args[itr + 3]
                    self.loadFromConfig(self.config_loc)
                    self.requestApiToken()
                    if dataExportType =='stream' or dataExportType =='query':
                        self.getExport(exportGuid, exportFile, dataExportType )
                    else:
                        print('valid data export types are stream or query')
                        exit(1)
                else:
                    print('Missing the Export Profile GUID or Data Export Type ')
                    exit(1)

            if (args[itr] == '--pe') or (args[itr] == '--poll_export'):
                if itr == (len(args) - 3):
                    exportGuid = args[itr + 1]
                    Poll = args[itr + 2]
                    # requests = self.arc_url + 'export_profiles/' + exportGuid + '/export'
                    self.loadFromConfig(self.config_loc)
                    self.requestApiToken()
                    self.pollExport(exportGuid, 'stream', int(Poll))
                else:
                    print('Missing the Export Profile GUID or Poll frequency')
                    exit(1)

        print('Use one of the following commands:'
              '\nAPI CALL REQUIRED:'
              '\n--get_Export (--ge)            Export_Profile_GUID DataExportType Export_File_Name'
              '\n--poll_Export (--pe)           Export_Profile_GUID Freqency'

              '\n\nOPTIONAL:'
              '\n--config (--c)                     configfile.json'
              '\n--auth_url                         ping_authentication_url_override'
              '\n--arc_url                          arc_url_override'
              '\n--client_id (--id)                 client_id_override'
              '\n--client_secret (--s)              client_secret_override'

              '\n\nOUTPUT SUPPORTED:'
              '\n--output_csv (--csv)'
              '\n--verbose (--v)'
              )


# Run main if this file is called directly
if __name__ == '__main__':
    export = ArcExport()
    export.main()
