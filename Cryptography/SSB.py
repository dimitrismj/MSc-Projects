# Ψηφιακή Υπογραφή χωρίς Random Oracles
#
#
#
# Εισαγωγή των απαραίτητων κλάσεων από την βιβλιοθήκη Charm
from toolbox.pairinggroup import *
from charm.engine.util import *

debug = False

# Αυτή είναι και η κύρια κλάση  μέσα στην οποία υλοποιούνται οι συναρτήσεις όπως ορίζει το πρωτόκολλο  SSB
class SSB():
    
    # Τυπική συνάρτηση κατά τον ορισμό κλάσεων στην Python που στόχο έχει την αρχικοποίηση ενός αντικειμένου της κλάσης SSB
    def __init__(self, groupObj):
        global group
        group = groupObj
        
        
    # Συνάρτηση παραγωγής του δημόσιου και ιδιωτικού κλειδιού που  θα χρησιμοποιηθούν στην ψηφιακή υπογραφή      
    def keygen(self):
        P, x, y  = group.random(G2), group.random(ZR), group.random(ZR)
        U = P * x
        V = P * y
        pk = { 'P':P , 'U':U, 'V':V } # Δημόσιο κλειδί για την υπογραφή
        sk = { 'x':x, 'y':y } # Ιδιωτικό κλειδί για την υπογραφή
        return (pk, sk)
        
        
    
    # Συνάρτηση υπογραφής του μηνύματος    
    def sign(self, x, y,  message):
        r = group.random(ZR)
        m = group.hash(message, ZR)
        if debug: print("Message => '%s'" % message)
        a = 1 / (sk['x'] + m + sk['y'] * r)  # Το κλάσμα 1/x+m+yr υπολογίζεται modulo q και η περίπτωση που προκύπτει ο παρονόμαστης ίσος με το μηδέν αποφεύγεται με διαφορετική επιλογή του r.
        s = a * P
        sig = {'s':s, 'r':r}
        return sig
        
    # Συνάρτηση επαλήθευσης της υπογραφής του μηνύματος    
    def verify(self, pk, sig, message):
        m = group.hash(message, ZR)
        if pair(sig['s'], pk['U'] + m*pk['P'] + sig['r']*pk['V'] ) == pair(pk['P'], pk['P']):
            return True  
        else:
            return False 
            
# Συνάρτηση  main η οποία εφαρμόζει το πρωτόκολλο SSB without Oracle  για το κείμενο "Welcome to Cryptography!!!!!"
def main():
    groupObj = PairingGroup('d224.param', 1024)
    
    m = "Welcome to Cryptography!!!"
    ssb = BLS(groupObj)
    
    (pk, sk) = ssb.keygen()
    
    sig = ssb.sign(sk['x'], m)
    result = ssb.verify(pk, sig, m)
    
    if debug: print("Message: '%s'" % m)
    if debug: print("Signature: '%s'" % sig) 
    assert result, "INVALID signature!"    
    if debug: print("Successful Verification!!!")
    
    
if __name__ == "__main__":
    debug = True
    main()


