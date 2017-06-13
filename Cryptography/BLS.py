# Ψηφιακή Υπογραφή BLS
#
#
#
# Εισαγωγή των απαραίτητων κλάσεων από την βιβλιοθήκη Charm
from toolbox.pairinggroup import *
from charm.engine.util import *

debug = False

# Αυτή είναι και η κύρια κλάση  μέσα στην οποία υλοποιούνται οι συναρτήσεις όπως ορίζει το πρωτόκολλο  BLS
class BLS():
    
    # Τυπική συνάρτηση κατά τον ορισμό κλάσεων στην Python που στόχο έχει την αρχικοποίηση ενός αντικειμένου της κλάσης BLS
    def __init__(self, groupObj):
        global group
        group = groupObj
    
    # Συνάρτηση για serialization του μηνύματος
    def dump(self, obj):
        ser_a = serializeDict(obj, group)
        return str(pickleObject(ser_a))
    
    # Συνάρτηση παραγωγής του δημόσιου και ιδιωτικού κλειδιού που  θα χρησιμοποιηθούν στην ψηφιακή υπογραφή      
    def keygen(self):
        P, x = group.random(G2), group.random(ZR)
        P_PUB = P * x
        pk = { 'P_PUB':P_PUB, 'P':P, }
        sk = { 'x':x }
        return (pk, sk)
     
    # Συνάρτηση υπογραφής του μηνύματος    
    def sign(self, x, message):
        M = self.dump(message)
        if debug: print("Message => '%s'" % M)
        sig = group.hash(M, G1) * x
        return sig
    
    # Συνάρτηση επαλήθευσης της υπογραφής του μηνύματος    
    def verify(self, pk, sig, message):
        M = self.dump(message)
        h = group.hash(M, G1)
        if pair(pk['P'], sig) == pair(pk['P_PUB'], h):
            return True  
        else:
            return False 
        
# Συνάρτηση  main η οποία εφαρμόζει το πρωτόκολλο BLS  για το κείμενο "Welcome to Cryptography!!!!!"
def main():
    groupObj = PairingGroup('d224.param', 1024)
    
    m = "Welcome to Cryptography!!!" 
    bls = BLS(groupObj)
    
    (pk, sk) = bls.keygen()
    
    sig = bls.sign(sk['x'], m)
    result = bls.verify(pk, sig, m)
    
    if debug: print("Message: '%s'" % m)
    if debug: print("Signature: '%s'" % sig)     
    assert result, "INVALID signature!"
    if debug: print("Successful Verification!!!")
    
if __name__ == "__main__":
    debug = True
    main()
    
