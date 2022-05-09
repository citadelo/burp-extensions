#######################
# Burp related imports
from burp import IBurpExtender
from burp import IHttpListener
from burp import ITab

############################
# Java Swing related imports
from javax.swing import JTabbedPane
from javax.swing import JTextField
from javax.swing import JButton
from javax.swing import JPanel
from javax.swing import JLabel

#################
# python imports
import hmac
import base64
import hashlib
import uuid
import sys
import os


EXTENSION_NAME = 'Request signer'


class BurpExtender(IBurpExtender, IHttpListener, ITab):

    #override
    def registerExtenderCallbacks(self, callbacks):

        # setup burp local variables and helpers
        # callbacks - allow extension to perform burp actions like - extension name, register request listeners, check scope, issue alert, etc.
        # helpers - allow  
        self._callbacks = callbacks
        self._helpers = callbacks.getHelpers()
        
        callbacks.setExtensionName(EXTENSION_NAME)
        callbacks.registerHttpListener(self)
        
        # create simple extionsion UI
        # new tab in Burp window
        self._mainTabP = JTabbedPane()
        settingsP = JPanel()

        self._mainTabP.addTab("Settings", settingsP)

        self._keyFileLocationTF = JTextField('Put here the key file location, and reload', 50)
        self._keyTF = JTextField('YzMwNjg3MzQ2NzNkNjVlNWIzNmQ5YWRkMTFkY2MzYTRjNzU5YThhOTE0NzE2NDNkY2VlNjFkODQ5OTMyYzFkNQ==', 50)

        # create buttons with event handler
        reloadButtonFile = JButton("Load key from file", actionPerformed=self.reloadFileButtonEvent)
        reloadButton = JButton("Load key from input", actionPerformed=self.reloadButtonEvent)

        settingsP.add(JLabel("Key file location:"))
        settingsP.add(self._keyFileLocationTF)
        settingsP.add(reloadButtonFile)
        settingsP.add(JLabel("Base64 encoded key:"))
        settingsP.add(self._keyTF)
        settingsP.add(reloadButton)

        self._callbacks.addSuiteTab(self)

        self.reloadButtonEvent(None)

        print('For settings see "{}" tab'.format(EXTENSION_NAME))


    def reloadFileButtonEvent(self, event):
        """
        Reload key from file. Take JTextField input - file path/name, read file and set content to key JTetField.
        """

        key = self.reloadKeyFromFile(self._keyFileLocationTF.getText())
        self._keyTF.setText(key)

        self.loadKeyFromTF()


    def reloadButtonEvent(self, event):
        """
        Reload key from input.
        """

        self.loadKeyFromTF()


    def loadKeyFromTF(self):
        """
        Load key from the text field and decode it.
        """

        try:
            self.key = base64.b64decode(self._keyTF.getText())

            if not self.key:

                raise Exception('empty key')

            print('Using key: {}'.format(base64.b64encode(self.key)))

        except Exception as e:

            msg = 'Invalid key loaded: {}, error: {}'.format(self.key, e)

            print(msg)
            self._callbacks.issueAlert(msg)


    def getHeaderValue(self, header_name, header_list):
        """
        Find HTTP header in request header list.
        """

        for header in header_list:
            # print('searching value "{}" in "{}" '.format(header_name + ': ', header))
            if header.startswith(header_name + ': '):

                return header.split(header_name + ': ')[1]


    def removeHeader(self, header_name, header_list):
        """
        Remove HTTP header from the request header list. Return updated list.
        """

        new_headers = []

        for header in header_list:
            if not header.startswith(header_name + ': '):

                new_headers.append(header)

        return new_headers


    def reloadKeyFromFile(self, file_path):
        """
        If file_path is a file, it will read the fiel content and load key (parser logic can be implemented)

        If file_path is a directory, it will load the latest .txt file and load key (parser logic can be implemented)

        Example of usage:

        Second scenario was used in case of the mobile application logged key to log files. We needed to automatically load the valid key.
        """

        latest_file = None
        latest_file_mtime = 0
        key = None

        if os.path.isdir(file_path):

            print('Searching for latest *.txt file')

            for root, dirs, files in os.walk(file_path, topdown=False):
                for name in files:

                    if name.endswith('.txt'):

                        f = os.path.join(root, name)
                        mtime = os.stat(f).st_mtime
                        
                        if mtime > latest_file_mtime:
                            latest_file_mtime = mtime
                            latest_file = f

        else:

            latest_file = file_path

        if latest_file and os.path.isfile(latest_file):

            print('Loading key from file: {}'.format(latest_file))

            with open(latest_file, 'r') as f:
                # if required implement parser logic to properly load a key
                key = f.read()
        else:

            msg = 'Key file not found: {}'.format(latest_file)

            print(msg)
            self._callbacks.issueAlert(msg)

        return key


    #override
    def processHttpMessage(self, toolFlag, messageIsRequest, currentRequest):
        """
        post /foo/bar
        host: example.com
        x-request-id: 5AB91111-9937-4853-A22D-E329238B7323
        signature: SHA-256=Iq7WcUph839/fq/Ic5GCG7xMNxO6EOYrCfOThU9iqfU=
        content-length: 44
        """

        if (toolFlag == self._callbacks.TOOL_EXTENDER 
                        or toolFlag == self._callbacks.TOOL_REPEATER
                        or toolFlag == self._callbacks.TOOL_INTRUDER
                        or toolFlag == self._callbacks.TOOL_SCANNER) and messageIsRequest:
                        
            requestInfo = self._helpers.analyzeRequest(currentRequest)

            # continue only for in scope requests
            if not self._callbacks.isInScope(requestInfo.getUrl()):

                return

            # prepare data to sign
            headers = requestInfo.getHeaders()
            headers_list = list(headers)

            first_header_parts = headers_list[0].split(' ')
            
            # in this case, e.g. in case of using repater, request-id ca not be sent twice the same, therofe, every time new one is generated
            new_request_id = str(uuid.uuid4()).upper()

            data_to_sign = '(request): {} {}'.format(first_header_parts[0].lower(), first_header_parts[1])
            data_to_sign += '\nhost: {}'.format(self.getHeaderValue("Host", headers_list))
            data_to_sign += '\nx-request-id: {}'.format(new_request_id)

            body_bytes = currentRequest.getRequest()[requestInfo.getBodyOffset():]

            if requestInfo.getMethod().lower() in ['post', 'put', 'patch']:

                sha256_req_checksum = hashlib.sha256(body_bytes).digest()
                sha256_req_checksum = base64.b64encode(sha256_req_checksum)
                data_to_sign += '\nbody-checksum: SHA-256={}'.format(sha256_req_checksum)
                data_to_sign += '\ncontent-length: {}'.format(self.getHeaderValue('Content-Length', headers_list))

            h = hmac.new(self.key, data_to_sign, hashlib.sha256)
            signature = base64.b64encode(h.digest())

            new_headers = self.removeHeader('Signature', headers_list)
            new_headers = self.removeHeader('X-Request-Id', new_headers)

            new_headers.append('Signature: signature="{}"'.format(signature))
            new_headers.append('X-Request-Id: {}'.format(new_request_id))

            newMessage = self._helpers.buildHttpMessage(new_headers, self._helpers.bytesToString(body_bytes))

            currentRequest.setRequest(newMessage)


    #override
    def getTabCaption(self):

        return EXTENSION_NAME
    
    #override
    def getUiComponent(self):
        
        return self._mainTabP

