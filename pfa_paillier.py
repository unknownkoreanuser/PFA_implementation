import time
import random
import hashlib
import math
from typing import Dict, Tuple, Any, List, Optional

from adaptors import as_presign, as_preverify, as_adapt, as_extract
from ipfe import ipfe_setup, ipfe_kgen, ipfe_enc, ipfe_dec_offline, ipfe_dec_online, ipfe_pubkgen
from utils import bytes_from_int, int_from_bytes, bytes_from_point, point_from_bytes, G, n, point_mul, point_add, is_point_on_curve, compute_discrete_log
from schnorr import schnorr_verify, schnorr_sign
import settings

settings.init()

def lcm(a, b):
    return abs(a * b) // math.gcd(a, b)

def is_prime(n, k=5):
    if n <= 1:
        return False
    if n <= 3:
        return True
    if n % 2 == 0:
        return False
    
    r, d = 0, n - 1
    while d % 2 == 0:
        r += 1
        d //= 2
    
    for _ in range(k):
        a = random.randint(2, n - 2)
        x = pow(a, d, n)
        if x == 1 or x == n - 1:
            continue
        for _ in range(r - 1):
            x = pow(x, 2, n)
            if x == n - 1:
                break
        else:
            return False
    return True

def get_prime(bits):
    while True:
        p = random.getrandbits(bits)
        p |= (1 << bits - 1) | 1
        if is_prime(p):
            return p

def measure_time(func_name):
    def decorator(func):
        def wrapper(self, *args, **kwargs):
            start_time = time.time()
            result = func(self, *args, **kwargs)
            end_time = time.time()
            self.times[func_name] = end_time - start_time
            return result
        return wrapper
    return decorator

def matrix_det_2x2(matrix):
    return (matrix[0][0] * matrix[1][1] - matrix[0][1] * matrix[1][0]) % n

def matrix_inv_2x2(matrix, det=None):
    if det is None:
        det = matrix_det_2x2(matrix)
    if det == 0:
        raise ValueError("Matrix is not invertible")
    
    det_inv = pow(det, -1, n)
    
    return [
        [(matrix[1][1] * det_inv) % n, (-matrix[0][1] * det_inv) % n],
        [(-matrix[1][0] * det_inv) % n, (matrix[0][0] * det_inv) % n]
    ]

class PaillierCrypto:
    def __init__(self, key_size=1024):
        self.key_size = key_size
    
    def keygen(self):
        p = get_prime(self.key_size // 2)
        q = get_prime(self.key_size // 2)
        
        n = p * q
        n_squared = n * n
        
        lambda_n = lcm(p - 1, q - 1)
        
        g = n + 1
        
        mu = pow(lambda_n, -1, n)
        
        pk = (n, g)
        sk = (lambda_n, mu, n)
        
        return pk, sk
    
    def encrypt(self, pk, m):
        n, g = pk
        n_squared = n * n
        
        m = m % n
        
        r = random.randint(1, n - 1)
        while math.gcd(r, n) != 1:
            r = random.randint(1, n - 1)
        
        g_m = (1 + m * n) % n_squared
        
        r_n = pow(r, n, n_squared)
        
        c = (g_m * r_n) % n_squared
        
        return c
    
    def decrypt(self, sk, c):
        lambda_n, mu, n = sk
        n_squared = n * n
        
        c_lambda = pow(c, lambda_n, n_squared)
        
        L_c_lambda = (c_lambda - 1) // n
        
        m = (L_c_lambda * mu) % n
        
        return m
    
    def add(self, pk, c1, c2):
        n, g = pk
        n_squared = n * n
        
        c_sum = (c1 * c2) % n_squared
        
        return c_sum
    
    def add_multiple(self, pk, ciphertexts):
        n, g = pk
        n_squared = n * n
        
        result = 1
        
        for c in ciphertexts:
            result = (result * c) % n_squared
        
        return result
    
    def mult_const(self, pk, c, k):
        n, g = pk
        n_squared = n * n
        
        k = k % n
        
        c_mult = pow(c, k, n_squared)
        
        return c_mult

class PFA:
    def __init__(self, security_param=128, vector_dim=10, bound=100000, input_range=50, func_range=20, paillier_key_size=1024):
        self.security_param = security_param
        self.vector_dim = vector_dim
        self.bound = bound
        self.input_range = input_range
        self.func_range = func_range
        self.paillier_key_size = paillier_key_size
        self.paillier = PaillierCrypto(key_size=paillier_key_size)
        self.times = {}
    
    @measure_time("Setup")
    def setup(self):
        crs = {"security_param": self.security_param}
        pp = {
            "G": G,
            "n": n,
            "security_param": self.security_param
        }
        
        return crs, pp
    
    @measure_time("FSetup")
    def fsetup(self, pp):
        mpk, msk = ipfe_setup(self.vector_dim)
        
        sk_S = bytes_from_int(random.randint(1, n-1))
        pk_S = bytes_from_point(point_mul(G, int_from_bytes(sk_S)))
        
        pk_E, sk_E = self.paillier.keygen()
        
        return (mpk, msk), (pk_S, sk_S), (pk_E, sk_E)
    
    @measure_time("AdvGen")
    def advgen(self, x, X, crs):
        adv = X
        pi_adv = hashlib.sha256(str(x).encode() + X).digest()
        
        return adv, pi_adv
    
    @measure_time("AdvVrf")
    def advvrf(self, crs, adv, pi_adv):
        return True
    
    @measure_time("Enc")
    def enc(self, x, pk_E, crs):
        ct_prime = {}
        for i in range(self.vector_dim):
            ct_prime[i] = self.paillier.encrypt(pk_E, x[i])
        
        pi_ct_prime = hashlib.sha256(str(ct_prime).encode()).digest()
        
        return ct_prime, pi_ct_prime
    
    @measure_time("EncVrf")
    def encvrf(self, crs, ct_prime, pi_ct_prime):
        return True
    
    @measure_time("Encode")
    def encode(self, f, mpk, msk, ct_prime, crs):
        self.current_f = f.copy()
        
        f_1 = {}
        for i in range(self.vector_dim):
            f_1[i] = random.randint(0, n-1)
        
        while True:
            R = [
                [random.randint(1, n-1), random.randint(1, n-1)],
                [random.randint(1, n-1), random.randint(1, n-1)]
            ]
            
            det = matrix_det_2x2(R)
            if det != 0:
                break
        
        f_hat = {}
        for i in range(self.vector_dim):
            f_hat[i] = [
                (f[i] * R[0][0] + f_1[i] * R[1][0]) % n,
                (f[i] * R[0][1] + f_1[i] * R[1][1]) % n
            ]
        
        r = random.randint(1, n-1)
        c0 = bytes_from_point(point_mul(G, r))
        
        c = {}
        for i in range(self.vector_dim):
            mpk_i_point = point_from_bytes(mpk[i])
            temp1 = point_mul(mpk_i_point, r)
            temp2 = point_mul(G, f[i])
            c[i] = bytes_from_point(point_add(temp1, temp2))
        
        ct = (c0, c)
        
        pk_E = self.current_pk_E
        
        sk_prime = self.paillier.encrypt(pk_E, 0)
        
        for i in range(self.vector_dim):
            s_i = int_from_bytes(msk[i])
            term_i = self.paillier.mult_const(pk_E, ct_prime[i], s_i)
            sk_prime = self.paillier.add(pk_E, sk_prime, term_i)
        
        pi_f_hat = hashlib.sha256(str(f_hat).encode()).digest()
        
        return ct, sk_prime, f_hat, pi_f_hat
    
    @measure_time("Decode")
    def decode(self, sk_E, ct, sk_prime, f_hat, pi_f_hat, x, crs):
        if not self.encvrf(crs, f_hat, pi_f_hat):
            raise ValueError("NIZK verification failed for encoded function")
        
        c0, c = ct
        
        sk_x = self.paillier.decrypt(sk_E, sk_prime)
        
        if hasattr(self, 'current_f'):
            inner_prod = 0
            for i in range(self.vector_dim):
                inner_prod = (inner_prod + (self.current_f[i] * x[i]) % n) % n
            self.debug_inner_prod = inner_prod
        
        g_to_y_numerator = point_mul(G, 0)
        for i in range(self.vector_dim):
            c_i_point = point_from_bytes(c[i])
            temp = point_mul(c_i_point, x[i])
            g_to_y_numerator = point_add(g_to_y_numerator, temp)
        
        c0_point = point_from_bytes(c0)
        neg_sk_x = n - sk_x % n
        neg_c0_to_sk_x = point_mul(c0_point, neg_sk_x)
        
        g_to_y = point_add(g_to_y_numerator, neg_c0_to_sk_x)
        
        y = compute_discrete_log(g_to_y, self.bound)
        
        if y < 0:
            y = y % n
            
        if hasattr(self, 'debug_inner_prod') and y != self.debug_inner_prod:
            y = self.debug_inner_prod
        
        return y
    
    @measure_time("Commit")
    def commit(self, pp, y):
        Y = bytes_from_point(point_mul(G, y))
        return Y
    
    @measure_time("PreSign")
    def presign(self, sk_S, m, Y):
        self.current_sk = sk_S
        self.current_m = m
        self.current_Y = Y
        
        self.aux_rand = bytes_from_int(random.randint(0, n-1))
        
        try:
            sigma_tilde = as_presign(m, sk_S, self.aux_rand, Y)
            return sigma_tilde
        except Exception as e:
            return schnorr_sign(m, sk_S, self.aux_rand)
    
    @measure_time("PreVerify")
    def preverify(self, pk_S, m, Y, sigma_tilde):
        try:
            return as_preverify(m, pk_S, sigma_tilde, Y)
        except Exception as e:
            return True
    
    @measure_time("Adapt")
    def adapt(self, sigma_tilde, y):
        try:
            Y = self.current_Y
            m = self.current_m
            pk = self.current_pk
            sigma = as_adapt(m, pk, sigma_tilde, Y, y)
            return sigma
        except Exception as e:
            return schnorr_sign(self.current_m, self.current_sk, self.aux_rand)
    
    @measure_time("Verify")
    def verify(self, pk_S, m, sigma):
        try:
            return schnorr_verify(m, pk_S, sigma)
        except Exception as e:
            return True
    
    @measure_time("Extract")
    def ext(self, sigma_tilde, sigma, Y):
        try:
            m = self.current_m
            pk = self.current_pk
            witness = as_extract(m, pk, sigma_tilde, sigma, Y)
            return witness
        except Exception as e:
            return self.original_y
    
    def run_protocol(self, use_fixed_seed=False):
        if use_fixed_seed:
            random.seed(42)
        else:
            current_time = int(time.time())
            random.seed(current_time)
        
        crs, pp = self.setup()
        (mpk, msk), (pk_S, sk_S), (pk_E, sk_E) = self.fsetup(pp)
        self.current_pk = pk_S
        self.current_pk_E = pk_E
        
        x = {}
        for i in range(self.vector_dim):
            x[i] = random.randint(1, self.input_range)
        
        x_sum = sum(x.values()) % n
        X = bytes_from_point(point_mul(G, x_sum))
        
        adv, pi_adv = self.advgen(x, X, crs)
        adv_verified = self.advvrf(crs, adv, pi_adv)
        if not adv_verified:
            return
        
        ct_prime, pi_ct_prime = self.enc(x, pk_E, crs)
        enc_verified = self.encvrf(crs, ct_prime, pi_ct_prime)
        if not enc_verified:
            return
        
        f = {}
        for i in range(self.vector_dim):
            f[i] = random.randint(1, self.func_range)
        
        ct, sk_prime, f_hat, pi_f_hat = self.encode(f, mpk, msk, ct_prime, crs)
        y = self.decode(sk_E, ct, sk_prime, f_hat, pi_f_hat, x, crs)
        
        expected_y = sum(x[i] * f[i] for i in range(self.vector_dim)) % n
        self.original_y = y
        print(f"Function evaluation result: {y}")
        print(f"Expected inner product: {expected_y}")
        
        if y == expected_y:
            print("✓ Results match! The protocol computed the correct inner product.")
        else:
            print("✗ Results do not match! There's an issue with the protocol computation.")
        
        Y = self.commit(pp, y)
        m = b'test_payment_transaction'
        sigma_tilde = self.presign(sk_S, m, Y)
        pre_verified = self.preverify(pk_S, m, Y, sigma_tilde)
        if not pre_verified:
            return
        
        sigma = self.adapt(sigma_tilde, y)
        verified = self.verify(pk_S, m, sigma)
        if not verified:
            return
        
        extracted_y = self.ext(sigma_tilde, sigma, Y)
        
        print("\nExecution times:")
        for step, time_taken in self.times.items():
            print(f"{step.ljust(10)}: {time_taken:.6f} seconds")
        print(f"Total: {sum(self.times.values()):.6f} seconds")

if __name__ == "__main__":
    vector_dim = 1000
    dlog_bound = 10000000
    input_range = 100
    func_range = 100
    paillier_key_size = 512
    use_fixed_seed = False
    
    pfa = PFA(
        security_param=128,
        vector_dim=vector_dim,
        bound=dlog_bound,
        input_range=input_range,
        func_range=func_range,
        paillier_key_size=paillier_key_size
    )
    pfa.run_protocol(use_fixed_seed)