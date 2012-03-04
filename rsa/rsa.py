#-*-coding:utf-8-*-
import base64

__author__ = 'wong2'
__date__ = '2011.3.9'

class RSA:
    
    def __init__(self, p, q):
        self.p, self.q = p, q
        self.n = p*q
        self.phi_n = (p-1)*(q-1)
        print "P: ", self.p
        print "Q: ", self.q
        print "n: ", self.n
        print "phi_n: ", self.phi_n
        self.genKey(self.p, self.q)

    def exgcd(self, r1, r2):
        s0, s1 = 1, 0
        t0, t1 = 0, 1
        q = r1/r2
        r1, r2 = r2, r1%r2
        while r2 != 0:
            s0, s1 = s1, s0-q*s1
            t0, t1 = t1, t0-q*t1
            q = r1/r2
            r1, r2 = r2, r1%r2
        return s1, t1
        
    def expo_mod(self, b, e, n):
        result = 1
        while e > 0:
            if e & 1 == 1:
                result = result * b % n
            e >>= 1
            b = b*b%n
        return result

    def genKey(self, p, q):
        self.k1 = 65537
        self.k2, m = self.exgcd(self.k1, self.phi_n)
        if self.k2<0:
            self.k2 += self.phi_n
        if m>0:
            m -= self.k1 

    def encrypt(self, x):
        return self.expo_mod(x, self.k1, self.n)

    def decrypt(self, y):
        y = int(y)
        num = self.expo_mod(y, self.k2, self.n)
        s = ''
        while num != 0:
            s += chr(num%1000)
            num /= 1000
        s = s[::-1]
        s_after_decode = base64.b64decode(s).decode("utf-8")
        return s_after_decode
    
    def encryptString(self, s):
        base64_s = base64.b64encode(s.encode("utf-8"))
        x = 0    
        for c in base64_s:
            x *= 1000
            x += ord(c)
        return self.encrypt(x)

if __name__ == '__main__':
    p = 33478071698956898786044169848212690817704794983713768568912431388982883793878002287614711652531743087737814467999489
    q = 36746043666799590428244633799627952632279158164343087642676032283815739666511279233373417143396810270092798736308917
    rsa = RSA(p, q)
    #y = rsa.encrypt("abcd")
    #x = rsa.decrypt(y)
    y = rsa.encryptString(u"今天气不错哈哈哈，abc哈哈哈")
    print y
    x = rsa.decrypt(y)
    print x
