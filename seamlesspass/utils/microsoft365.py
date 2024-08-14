import base64
import uuid
import requests

from xml.etree import ElementTree as ET

from .log import logger



class Microsoft365Helper:
    
    def __init__(self):
        self.tenant_domain: str = None
        self.resource: str = 'https://graph.windows.net'
        self.client_id: str = '1b730954-1685-4b74-9bfd-dac224a7b894' #Azure AD PowerShell
        self.proxies: dict = None
        self.headers = dict()
        self.headers['User-Agent'] = 'Mozilla/4.0 (compatible; MSIE 7.0; Windows NT 10.0; Win64; x64; Trident/7.0; .NET4.0C; .NET4.0E)'

    @staticmethod
    def from_options(options):
        self = Microsoft365Helper()

        if options.resource:
            self.resource = options.resource

        if options.client_id:
            self.client_id = options.client_id

        if options.proxies:
            self.proxies = {"http": options.proxies, "https": options.proxies}

        if options.user_agent:
            self.headers['User-Agent'] = options.user_agent

        self.tenant_domain = options.tenant

        return self



    def check_seamless_sso(self):
        email = f"info@{self.tenant_domain}"
        url = "https://login.microsoftonline.com/common/GetCredentialType"
        data = {
            "username": email,
            "isOtherIdpSupported": True,
            "checkPhones": True,
            "isRemoteNGCSupported": True,
            "isCookieBannerShown": False,
            "isFidoSupported": True,
            "isAccessPassSupported": True
        }
        
        try:
            response = requests.post(url, json=data, verify=False, headers=self.headers, proxies=self.proxies)
            response.raise_for_status()  # Raise an exception for HTTP errors
            response_json = response.json()
        except (requests.exceptions.RequestException,ValueError) as e :
            logger.debug(f"Failed to check if Seamless SSO is enabled: {e}")
            return False
        
        return "EstsProperties" in response_json and response_json["EstsProperties"].get("DesktopSsoEnabled") is True


    
    def get_dsso_token(self, kerberos_ticket: str):
        request_id = str(uuid.uuid4())
        
        logger.debug('Getting desktop SSO token using Kerberos ticket')

        url = f"https://autologon.microsoftazuread-sso.com/{self.tenant_domain}/winauth/trust/2005/windowstransport?client-request-id={request_id}"
        body = f"""<?xml version='1.0' encoding='UTF-8'?>
        <s:Envelope xmlns:s='http://www.w3.org/2003/05/soap-envelope' xmlns:wsse='http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-wssecurity-secext-1.0.xsd' xmlns:saml='urn:oasis:names:tc:SAML:1.0:assertion' xmlns:wsp='http://schemas.xmlsoap.org/ws/2004/09/policy' xmlns:wsu='http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-wssecurity-utility-1.0.xsd' xmlns:wsa='http://www.w3.org/2005/08/addressing' xmlns:wssc='http://schemas.xmlsoap.org/ws/2005/02/sc' xmlns:wst='http://schemas.xmlsoap.org/ws/2005/02/trust'>
            <s:Header>
                <wsa:Action s:mustUnderstand='1'>http://schemas.xmlsoap.org/ws/2005/02/trust/RST/Issue</wsa:Action>
                <wsa:To s:mustUnderstand='1'>https://autologon.microsoftazuread-sso.com/{self.tenant_domain}/winauth/trust/2005/windowstransport?client-request-id={request_id}</wsa:To>
                <wsa:MessageID>urn:uuid:{request_id}</wsa:MessageID>
            </s:Header>
            <s:Body>
                <wst:RequestSecurityToken Id='RST0'>
                    <wst:RequestType>http://schemas.xmlsoap.org/ws/2005/02/trust/Issue</wst:RequestType>
                    <wsp:AppliesTo>
                        <wsa:EndpointReference>
                            <wsa:Address>urn:federation:MicrosoftOnline</wsa:Address>
                        </wsa:EndpointReference>
                    </wsp:AppliesTo>
                    <wst:KeyType>http://schemas.xmlsoap.org/ws/2005/05/identity/NoProofKey</wst:KeyType>
                </wst:RequestSecurityToken>
            </s:Body>
        </s:Envelope>"""
        
        headers = self.headers.copy()
        headers.update({
            "SOAPAction": "http://schemas.xmlsoap.org/ws/2005/02/trust/RST/Issue",
            "Authorization": f"Negotiate {kerberos_ticket}",
            "Content-Type": "application/soap+xml; charset=utf-8"
        })
        
        
        response = requests.post(url, data=body, verify=False, headers=headers, proxies=self.proxies)
        #response.raise_for_status()
        if response.status_code == 200 and 'DesktopSsoToken' in response.text:
        
            xml_response = ET.fromstring(response.content)
            dsso_token = xml_response.find('.//DesktopSsoToken').text

            logger.info('Got Desktop SSO login token')
            logger.debug(dsso_token)
            return dsso_token

        elif response.status_code == 403:
            logger.error('Failed to authenticate to the cloud using the kerberos ticket. Are you sure provided ticket is valid and Desktop SSO is enabled?')
        else:
            logger.debug('Unexpected error encountered while trying to get Desktop SSO Token')
            response.raise_for_status()




    def get_access_token(self, dsso_token: str):
        logger.debug('Trying to get access token using desktop SSO token')

        url = f'https://login.microsoftonline.com/{self.tenant_domain}/oauth2/token'
        saml_assertion = f'<saml:Assertion xmlns:saml="urn:oasis:names:tc:SAML:1.0:assertion"><DesktopSsoToken>{dsso_token}</DesktopSsoToken></saml:Assertion>'
        b64_saml_assertion = base64.b64encode(saml_assertion.encode('utf-8')).decode('utf-8')
        
        token_body = {
            "grant_type": "urn:ietf:params:oauth:grant-type:saml1_1-bearer",
            "assertion": b64_saml_assertion,
            "client_id": self.client_id,
            "resource": self.resource,
            #"scope": "openid",
            #"redirect_uri": f"ms-appx-web://Microsoft.AAD.BrokerPlugin/{client_id}"
        }
        

        token_response = requests.post(url, data=token_body, verify=False, headers=self.headers, proxies=self.proxies)

        if token_response.status_code == 200:
            token = token_response.json()

            logger.info('Got access token')
            return token

        elif token_response.status_code == 400 and 'application/json' in token_response.headers.get('Content-Type'):
            response_json = token_response.json()
            error_message = 'Failed to get access token'
            if response_json.get('error'):
                error_message += ' :: ' + response_json.get('error')
            if response_json.get('error_description'):
                error_message += ' :: ' + response_json.get('error_description')
            else:
                error_message += ' :: ' + token_response.text

            logger.error(error_message)
        else:
            logger.debug('Unexpected error encountered while trying to get access token')

            token_response.raise_for_status()


    
    def get_access_token_with_kerberos_ticket(self, kerberos_ticket):
        
        dsso_token = self.get_dsso_token(kerberos_ticket)
        if dsso_token:
            access_token = self.get_access_token(dsso_token)
            return access_token