# Ταυτοτική Κρυπτογράφηση Boneh-Franklin
#
#
#
# Εισαγωγή των απαραίτητων κλάσεων από την βιβλιοθήκη Charm
from toolbox.pairinggroup import *
from toolbox.hash_module import *
from toolbox.IBEnc import *

debug = False

# Αυτή είναι και η κύρια κλάση  μέσα στην οποία υλοποιούνται οι συναρτήσεις όπως ορίζει το πρωτόκολλο των Boneh-Franklin
class IBE_BasicIdent(IBEnc):
    
    # Τυπική συνάρτηση κατά τον ορισμό κλάσεων στην Python που στόχο έχει την αρχικοποίηση ενός αντικειμένου της κλάσης  IBE_BasicIdent 
    def __init__(self, groupObj):
        IBEnc.__init__(self)
        global group, h
        group = groupObj
        h = Hash('sha1', group.Pairing)
        
    
    # Αποτελεί την πρώτη συνάρτηση του πρωτοκόλλου και η οποία παράγει και επιστρέφει  το δημόσιο κλειδί  κρυπτογράφησης και ένα κύριο ιδιωτικό κλειδί (master key)   
    def setup(self):
        s, P = group.random(ZR), group.random(G2)
        P_PUB = s * P 
        pk = { 'P':P, 'P_PUB':P_PUB } # Το public key κρυπτογράφησης
        sk = { 's':s } # Το master-key το οποίο θα χρησιμοποιήσω για να πιστοποιήσω την αυθεντικότητα μου στον PKG ώστε να μου εκδώσει private key βάση της ταυτότητας μου, και με το οποίο θα αποκρυπτογραφήσω το μήνυμα                                            
        if(debug):
            print("Public key parameters...")
            group.debug(pk)
            print("Master key parameters...")
            group.debug(sk)
        return (pk, sk)
    
    # Συνάρτηση η οποία εκτελείται από την μεριά του PKG και δέχεται ως είσοδο το master-key και ένα ID βάση του οποίου εξάγεται το ιδιωτικό κλειδί αποκρυπτογράφησης για τον παραλήπτη του μηνύματος
    def extract(self, sk, ID): 
        Q_ID = group.hash(ID, G1)       
        S_ID = sk['s'] * Q_ID
        d = { 'id':S_ID }
        if(debug):
            print("Key for id => '%s'" % ID)
            group.debug(d)
        return d
        
    # Συνάρτηση που μας κρυπτογραφεί το μήνυμα (plaintext) και δέχεται ως είσοδο 3 παραμέτρους: το δημόσιο κλειδί που θα χρησιμοποιηθεί για την κρυπτογράφηση, το ID και το ίδιο το plaintext 
    def encrypt(self, pk, ID, M): 
        r = group.random(ZR)
        Q_id = group.hash(ID, G1) 
        g_id = pair(Q_id, pk['P_PUB']) # Υπολογισμός της τιμής της pairing απεικόνισης με τα αντίστοιχα ορίσματα όπως προβλέπει το πρωτόκολλο
        
        enc_M = self.encodeToZ(M)
        if group.validSize(enc_M):
            C = { 'U':r * pk['P'], 'V':enc_M ^ h.hashToZn(g_id ** r) } # Εφαρμογή τού τύπου με το XOR για την κρυπτογράφηση του μηνύματος
        else:
            print("Message cannot be encoded.")
            return None

        if(debug):
            print('\nEncrypt...')
            print('enc_M => %s' % enc_M)
            group.debug(C)
        return C
    
    # Συνάρτηση που αποκρυπτογραφεί το κρυπτογραφημένο μήνυμα C με χρήση του private key που πήραμε από τον PKG
    def decrypt(self, pk, d, C):
        U, V = C['U'], C['V']
        dec_M= V ^ h.hashToZn(pair(d['id'], U)) # Εφαρμογή του XOR για την αποκρυπτογράφηση του μηνύματος
        M = self.decodeFromZ(dec_M)

        if(debug):
            print('\nDecrypt....')
            
        if U == r * pk['P']:
            if debug: print("Successful Decryption!!!")
            return M
        if debug: print("Decryption Failed!!!")
        return None

    # Μετατροπή σε ακέραιο το string του μηνύματος
    def encodeToZ(self, message):
        return integer(message)
        
    # Μετατροπή της ακέραιας αναπαράστασης του μηνύματος  σε string 
    def decodeFromZ(self, element):
        if type(element) == integer:
            msg = int2Bytes(element)
            return bytes.decode(msg, 'utf8') 
        return None
     
# Συνάρτηση  main η οποία εφαρμόζει το πρωτόκολλο  ταυτοτικής κρυπτογράφησης για το κείμενο "Welcome to Cryptography!!!!!"
def main():
    groupObj = PairingGroup('d224.param', 1024)    
    ibe = IBE_BasicIdent(groupObj)
    
    (pk, sk) = ibe.setup()
    
    ID = 'someone@email.com'
    d = ibe.extract(sk, ID)
    
    M = "Welcome to Cryptography!!!!!"
    C = ibe.encrypt(pk, ID, M)

    msg = ibe.decrypt(pk, d, C)
    assert msg == m,  "Failed decrypt: \n%s\n%s" % (msg, M)
    
        
if __name__ == "__main__":
    debug = True
    main()
