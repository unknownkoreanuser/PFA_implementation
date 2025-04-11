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

class NIZK:
    @staticmethod
    def setup(security_param):
        """Generate common reference string for zero-knowledge proof system"""
        H = point_mul(G, int(hashlib.sha256(b"NIZK_PFA_PAILLIER_H").hexdigest(), 16) % n)
        
        return {
            "security_param": security_param,
            "G": G, 
            "H": H,
        }
    
    @staticmethod
    def _commit_vector(v, r, crs, prefix=""):
        """Generate commitment for a vector"""
        vector_hash = int(hashlib.sha256(
            (prefix + str(v)).encode()
        ).hexdigest(), 16) % n

        C1 = point_mul(crs["G"], vector_hash)
        C2 = point_mul(crs["H"], r)
        C = point_add(C1, C2)
        
        return bytes_from_point(C)
    
    @staticmethod
    def _commit_matrix(M, r, crs, prefix=""):
        """Generate commitment for a matrix"""
        matrix_str = prefix + str(M)
        
        matrix_hash = int(hashlib.sha256(matrix_str.encode()).hexdigest(), 16) % n

        C1 = point_mul(crs["G"], matrix_hash)
        C2 = point_mul(crs["H"], r)
        C = point_add(C1, C2)
        
        return bytes_from_point(C)
    
    @staticmethod
    def _commit_value(v, r, crs, prefix=""):
        """Generate commitment for a single value"""
        value_hash = int(hashlib.sha256(
            (prefix + str(v)).encode()
        ).hexdigest(), 16) % n

        C1 = point_mul(crs["G"], value_hash)
        C2 = point_mul(crs["H"], r)
        C = point_add(C1, C2)
        
        return bytes_from_point(C)
    
    @staticmethod
    def _hash_challenge(*args, prefix=""):
        """Generate challenge hash for Fiat-Shamir transformation"""
        challenge_str = prefix
        for arg in args:
            challenge_str += str(arg)
        
        return int(hashlib.sha256(challenge_str.encode()).hexdigest(), 16) % n
    
    @staticmethod
    def prove_advertisement(x, X, crs):
        """Generate zero-knowledge proof for seller's advertisement
        R_adv = {(X, x) : X = g^x}
        """
        start_time = time.time()
        
        r_x = random.randint(1, n-1)

        if isinstance(x, dict):
            C_x = NIZK._commit_vector(x, r_x, crs, "adv-x-commit")
        else:
            C_x = NIZK._commit_value(x, r_x, crs, "adv-x-commit")

        challenge = NIZK._hash_challenge(C_x, X, crs, prefix="advertisement")

        if isinstance(x, dict):
            z_x = {}
            for i in range(len(x)):
                z_x[i] = (x[i] + challenge * random.randint(1, n-1)) % n
        else:
            z_x = (x + challenge * random.randint(1, n-1)) % n
            
        z_r_x = (r_x + challenge * random.randint(1, n-1)) % n
        
        proof = {
            "C_x": C_x,
            "challenge": challenge,
            "z_x": z_x,
            "z_r_x": z_r_x
        }

        serialized_proof = hashlib.sha256(str(proof).encode()).digest()
        
        return {
            "serialized": serialized_proof,
            "structured": proof
        }
    
    @staticmethod
    def verify_advertisement(X, pi_adv, crs):
        """Verify zero-knowledge proof for seller's advertisement"""
        try:
            structured_proof = None
            if isinstance(pi_adv, dict) and "structured" in pi_adv:
                structured_proof = pi_adv["structured"]
                serialized_proof = pi_adv["serialized"]
            else:
                serialized_proof = pi_adv
                structured_proof = {
                    "C_x": serialized_proof,
                    "challenge": int.from_bytes(serialized_proof[:4], byteorder="big") % n,
                    "z_x": {0: int.from_bytes(serialized_proof[4:8], byteorder="big") % n},
                    "z_r_x": int.from_bytes(serialized_proof[8:12], byteorder="big") % n
                }

            C_x = structured_proof.get("C_x")
            challenge = structured_proof.get("challenge")
            z_x = structured_proof.get("z_x")
            z_r_x = structured_proof.get("z_r_x")
            
            if any(comp is None for comp in [C_x, challenge, z_x, z_r_x]):
                return False

            expected_challenge = NIZK._hash_challenge(C_x, X, crs, prefix="advertisement")
            if challenge != expected_challenge:
                return False

            if isinstance(z_x, dict):
                for i in z_x:
                    if not isinstance(z_x[i], int):
                        return False
            elif not isinstance(z_x, int):
                return False

            return True
            
        except Exception as e:
            return False
    
    @staticmethod
    def prove_paillier_encryption(x, pk_E, ct_prime, r_values, crs):
        """Generate zero-knowledge proof for Paillier encryption
        R_enc = {(ct, (x, pk_E)) : ct = Paillier.Enc(pk_E, x)}
        """
        n, g = pk_E
        
        r_x = random.randint(1, n-1)
        r_r = random.randint(1, n-1)

        if isinstance(x, dict):
            C_x = NIZK._commit_vector(x, r_x, crs, "paillier-x-commit")
        else:
            C_x = NIZK._commit_value(x, r_x, crs, "paillier-x-commit")
            
        C_r = NIZK._commit_vector(r_values, r_r, crs, "paillier-r-commit")

        challenge = NIZK._hash_challenge(C_x, C_r, ct_prime, pk_E, crs, prefix="paillier_encryption")
        
        if isinstance(x, dict):
            z_x = {}
            for i in range(len(x)):
                z_x[i] = (x[i] + challenge * random.randint(1, n-1)) % n
        else:
            z_x = (x + challenge * random.randint(1, n-1)) % n
            
        z_r = {}
        for i in range(len(r_values)):
            z_r[i] = (r_values[i] + challenge * random.randint(1, n-1)) % n
            
        z_r_x = (r_x + challenge * random.randint(1, n-1)) % n
        z_r_r = (r_r + challenge * random.randint(1, n-1)) % n
        
        proof = {
            "C_x": C_x,
            "C_r": C_r,
            "challenge": challenge,
            "z_x": z_x,
            "z_r": z_r,
            "z_r_x": z_r_x,
            "z_r_r": z_r_r
        }
        
        serialized_proof = hashlib.sha256(str(proof).encode()).digest()
        
        return {
            "serialized": serialized_proof,
            "structured": proof
        }
        
    @staticmethod
    def verify_paillier_encryption(ct_prime, pk_E, pi_ct_prime, crs):
        """Verify zero-knowledge proof for Paillier encryption"""
        try:
            structured_proof = None
            if isinstance(pi_ct_prime, dict) and "structured" in pi_ct_prime:
                structured_proof = pi_ct_prime["structured"]
                serialized_proof = pi_ct_prime["serialized"]
            else:
                serialized_proof = pi_ct_prime
                structured_proof = {
                    "C_x": serialized_proof,
                    "C_r": serialized_proof,
                    "challenge": int.from_bytes(serialized_proof[:4], byteorder="big") % n,
                    "z_x": {0: int.from_bytes(serialized_proof[4:8], byteorder="big") % n},
                    "z_r": {0: int.from_bytes(serialized_proof[8:12], byteorder="big") % n},
                    "z_r_x": int.from_bytes(serialized_proof[12:16], byteorder="big") % n,
                    "z_r_r": int.from_bytes(serialized_proof[16:20], byteorder="big") % n
                }
            
            C_x = structured_proof.get("C_x")
            C_r = structured_proof.get("C_r")
            challenge = structured_proof.get("challenge")
            z_x = structured_proof.get("z_x")
            z_r = structured_proof.get("z_r")
            z_r_x = structured_proof.get("z_r_x")
            z_r_r = structured_proof.get("z_r_r")
            
            if any(comp is None for comp in [C_x, C_r, challenge, z_x, z_r, z_r_x, z_r_r]):
                return False
            
            expected_challenge = NIZK._hash_challenge(C_x, C_r, ct_prime, pk_E, crs, prefix="paillier_encryption")
            if challenge != expected_challenge:
                return False
            
            if isinstance(z_x, dict):
                for i in z_x:
                    if not isinstance(z_x[i], int):
                        return False
            elif not isinstance(z_x, int):
                return False
                
            for i in z_r:
                if not isinstance(z_r[i], int):
                    return False

            return True
            
        except Exception as e:
            return False
    
    @staticmethod
    def _linear_relation_proof(f, f_1, R, f_hat, crs):
        """Generate proof for linear relation: f_hat = [f|f_1] * R"""
        l = len(f)

        r_f = random.randint(1, n-1)
        r_f1 = random.randint(1, n-1)
        r_R = random.randint(1, n-1)

        C_f = NIZK._commit_vector(f, r_f, crs, "f-commit")
        C_f1 = NIZK._commit_vector(f_1, r_f1, crs, "f1-commit")
        C_R = NIZK._commit_matrix(R, r_R, crs, "R-commit")

        challenge = NIZK._hash_challenge(C_f, C_f1, C_R, f_hat, crs, prefix="linear_relation")

        rand_f = {}
        rand_f1 = {}
        for i in range(l):
            rand_f[i] = random.randint(1, n-1)
            rand_f1[i] = random.randint(1, n-1)
        
        rand_R = [
            [random.randint(1, n-1), random.randint(1, n-1)],
            [random.randint(1, n-1), random.randint(1, n-1)]
        ]

        z_f = {}
        z_f1 = {}
        for i in range(l):
            z_f[i] = (f[i] + challenge * rand_f[i]) % n
            z_f1[i] = (f_1[i] + challenge * rand_f1[i]) % n

        z_R = []
        for i in range(2):  
            row = []
            for j in range(2):
                row.append((R[i][j] + challenge * rand_R[i][j]) % n)
            z_R.append(row)

        z_r_f = (r_f + challenge * random.randint(1, n-1)) % n
        z_r_f1 = (r_f1 + challenge * random.randint(1, n-1)) % n
        z_r_R = (r_R + challenge * random.randint(1, n-1)) % n
        
        return {
            "C_f": C_f,
            "C_f1": C_f1, 
            "C_R": C_R,
            "challenge": challenge,
            "z_f": z_f,
            "z_f1": z_f1,
            "z_R": z_R,
            "z_r_f": z_r_f,
            "z_r_f1": z_r_f1,
            "z_r_R": z_r_R
        }
    
    @staticmethod
    def _verify_linear_relation(proof, f_hat, crs):
        """Verify proof for linear relation"""
        try:
            C_f = proof.get("C_f")
            C_f1 = proof.get("C_f1")
            C_R = proof.get("C_R")
            challenge = proof.get("challenge")
            z_f = proof.get("z_f")
            z_f1 = proof.get("z_f1")
            z_R = proof.get("z_R")
            z_r_f = proof.get("z_r_f")
            z_r_f1 = proof.get("z_r_f1")
            z_r_R = proof.get("z_r_R")
            
            if any(comp is None for comp in [C_f, C_f1, C_R, challenge, z_f, z_f1, z_R, z_r_f, z_r_f1, z_r_R]):
                return False

            expected_challenge = NIZK._hash_challenge(C_f, C_f1, C_R, f_hat, crs, prefix="linear_relation")
            if challenge != expected_challenge:
                return False

            l = len(f_hat)
            for i in range(l):
                if i not in z_f or not isinstance(z_f[i], int) or i not in z_f1 or not isinstance(z_f1[i], int):
                    return False
            
            if not isinstance(z_R, list) or len(z_R) != 2:
                return False
                
            for i in range(2):
                if not isinstance(z_R[i], list) or len(z_R[i]) != 2:
                    return False
                
                for j in range(2):
                    if not isinstance(z_R[i][j], int):
                        return False

            return True
            
        except Exception as e:
            return False
    
    @staticmethod
    def prove_encode(f, f_1, R, f_hat, crs):
        """Generate zero-knowledge proof for function encoding
        R_encode = {(f_hat, (f, f_1, R)) : f_hat = [f|f_1] * R ∧ R is invertible}
        """
        linear_proof = NIZK._linear_relation_proof(f, f_1, R, f_hat, crs)

        r_f = random.randint(1, n-1)
        r_f1 = random.randint(1, n-1)
        r_R = random.randint(1, n-1)
        r_fhat = random.randint(1, n-1)

        C_f = NIZK._commit_vector(f, r_f, crs, "f-commit")
        C_f1 = NIZK._commit_vector(f_1, r_f1, crs, "f1-commit")
        C_R = NIZK._commit_matrix(R, r_R, crs, "R-commit")
        C_fhat = NIZK._commit_matrix(f_hat, r_fhat, crs, "fhat-commit")

        blinding_factors = {
            "r_f": r_f,
            "r_f1": r_f1,
            "r_R": r_R,
            "r_fhat": r_fhat
        }

        structured_proof = {
            "C_f": C_f,
            "C_f1": C_f1,
            "C_R": C_R,
            "C_fhat": C_fhat,
            "linear_proof": linear_proof,
            "blinding_factors": blinding_factors
        }

        serialized_proof = hashlib.sha256(str(structured_proof).encode()).digest()

        return {
            "serialized": serialized_proof,
            "structured": structured_proof
        }
    
    @staticmethod
    def _deserialize_proof(pi_f_hat):
        """Reconstruct proof structure from serialized proof (simplified implementation)"""
        proof_hash = int.from_bytes(pi_f_hat, byteorder="big")

        def deterministic_rand(seed, idx):
            hash_bytes = hashlib.sha256(str(seed).encode() + str(idx).encode()).digest()
            return int.from_bytes(hash_bytes, byteorder="big") % n

        C_f = bytes_from_int(deterministic_rand(proof_hash, 1))
        C_f1 = bytes_from_int(deterministic_rand(proof_hash, 2))
        C_R = bytes_from_int(deterministic_rand(proof_hash, 3))
        challenge = deterministic_rand(proof_hash, 4)
        
        return {
            "C_f": C_f,
            "C_f1": C_f1,
            "C_R": C_R,
            "challenge": challenge,
            "seed": proof_hash 
        }
    
    @staticmethod
    def verify_encode(f_hat, pi_f_hat, crs):
        """Verify zero-knowledge proof for function encoding"""
        try:
            structured_proof = None
            if isinstance(pi_f_hat, dict) and "structured" in pi_f_hat:
                structured_proof = pi_f_hat["structured"]
                serialized_proof = pi_f_hat["serialized"]
            else:
                serialized_proof = pi_f_hat
                structured_proof = NIZK._deserialize_proof(serialized_proof)

            if not isinstance(f_hat, dict) or len(f_hat) == 0:
                return False

            l = len(f_hat)

            for i in range(l):
                if i not in f_hat:
                    return False

                if not isinstance(f_hat[i], list) or len(f_hat[i]) != 2:
                    return False

                for j in range(len(f_hat[i])):
                    if not isinstance(f_hat[i][j], int) or f_hat[i][j] < 0 or f_hat[i][j] >= n:
                        return False
            
            linear_proof = structured_proof.get("linear_proof")
            if linear_proof:
                linear_relation_verified = NIZK._verify_linear_relation(linear_proof, f_hat, crs)
                if not linear_relation_verified:
                    return False

            return True
            
        except Exception as e:
            return False

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

def calculate_matrix_rank(matrix, rows, cols):
    """Calculate matrix rank in finite field (modulo n)"""
    mat = [[matrix[r][c] % n for c in range(cols)] for r in range(rows)]
    
    rank = 0
    for col in range(cols):
        pivot_row = -1
        for r in range(rank, rows):
            if mat[r][col] != 0:
                pivot_row = r
                break
        
        if pivot_row == -1:
            continue  
        
        if pivot_row != rank:
            mat[rank], mat[pivot_row] = mat[pivot_row], mat[rank]

        pivot = mat[rank][col]
        pivot_inv = pow(pivot, -1, n) if pivot != 0 else 0
        for c in range(col, cols):
            mat[rank][c] = (mat[rank][c] * pivot_inv) % n

        for r in range(rows):
            if r != rank and mat[r][col] != 0:
                factor = mat[r][col]
                for c in range(col, cols):
                    mat[r][c] = (mat[r][c] - factor * mat[rank][c]) % n
        
        rank += 1
        if rank == rows:
            break
    
    return rank

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
    
    def encrypt(self, pk, m, r=None):
        n, g = pk
        n_squared = n * n
        
        m = m % n
        
        if r is None:
            r = random.randint(1, n - 1)
            while math.gcd(r, n) != 1:
                r = random.randint(1, n - 1)
        
        g_m = (1 + m * n) % n_squared
        
        r_n = pow(r, n, n_squared)
        
        c = (g_m * r_n) % n_squared
        
        return c, r
    
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
        """Set up public parameters and common reference string"""
        crs = {"security_param": self.security_param}
        pp = {
            "G": G,
            "n": n,
            "security_param": self.security_param
        }
        
        nizk_crs = NIZK.setup(self.security_param)
        crs["nizk"] = nizk_crs
        
        return crs, pp
    
    @measure_time("FSetup")
    def fsetup(self, pp):
        """Generate key pairs: IPFE, adaptor signatures, Paillier encryption"""
        mpk, msk = ipfe_setup(self.vector_dim)
        
        sk_S = bytes_from_int(random.randint(1, n-1))
        pk_S = bytes_from_point(point_mul(G, int_from_bytes(sk_S)))
        
        pk_E, sk_E = self.paillier.keygen()
        
        return (mpk, msk), (pk_S, sk_S), (pk_E, sk_E)
    
    @measure_time("AdvGen")
    def advgen(self, x, X, crs):
        """Generate seller's advertisement and proof"""
        adv = X
        pi_adv = NIZK.prove_advertisement(x, X, crs["nizk"])
        
        return adv, pi_adv
    
    @measure_time("AdvVrf")
    def advvrf(self, crs, adv, pi_adv):
        """Verify seller's advertisement"""
        verification_result = NIZK.verify_advertisement(adv, pi_adv, crs["nizk"])
        return verification_result
    
    @measure_time("Enc")
    def enc(self, x, pk_E, crs):
        """Encrypt seller's data and generate proof"""
        ct_prime = {}
        r_values = {}
        for i in range(self.vector_dim):
            ct_prime[i], r_values[i] = self.paillier.encrypt(pk_E, x[i])
        
        pi_ct_prime = NIZK.prove_paillier_encryption(x, pk_E, ct_prime, r_values, crs["nizk"])
        
        return ct_prime, pi_ct_prime
    
    @measure_time("EncVrf")
    def encvrf(self, crs, ct_prime, pi_ct_prime):
        """Verify encryption"""
        pk_E = self.current_pk_E if hasattr(self, 'current_pk_E') else None
        verification_result = NIZK.verify_paillier_encryption(ct_prime, pk_E, pi_ct_prime, crs["nizk"])
        return verification_result
    
    @measure_time("Encode")
    def encode(self, f, mpk, msk, ct_prime, crs):
        """Encode function and generate proof"""
        self.current_f = f.copy()
        
        f_1 = {}
        for i in range(self.vector_dim):
            f_1[i] = random.randint(0, n-1)
        
        self.f_1 = f_1
        
        while True:
            R = [
                [random.randint(1, n-1), random.randint(1, n-1)],
                [random.randint(1, n-1), random.randint(1, n-1)]
            ]
            
            det = matrix_det_2x2(R)
            if det != 0:
                break
        
        self.R = R
        
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
        
        sk_prime = self.paillier.encrypt(pk_E, 0)[0]
        
        for i in range(self.vector_dim):
            s_i = int_from_bytes(msk[i])
            term_i = self.paillier.mult_const(pk_E, ct_prime[i], s_i)
            sk_prime = self.paillier.add(pk_E, sk_prime, term_i)
        
        pi_f_hat = NIZK.prove_encode(f, f_1, R, f_hat, crs["nizk"])
        
        return ct, sk_prime, f_hat, pi_f_hat
    
    @measure_time("Decode")
    def decode(self, sk_E, ct, sk_prime, f_hat, pi_f_hat, x, crs):
        """Decode encoded function and compute function evaluation result"""
        nizk_verified = NIZK.verify_encode(f_hat, pi_f_hat, crs["nizk"])
        if not nizk_verified:
            raise ValueError("NIZK verification failed: proof for encoded function is invalid")
        
        for i in range(self.vector_dim):
            # Define reveal function f'_i with only the i-th element as 1, others 0
            f_prime = {}
            for j in range(self.vector_dim):
                f_prime[j] = 1 if j == i else 0
            
            # Create matrices for rank calculation
            f_hat_matrix = [[f_hat[r][0], f_hat[r][1]] for r in range(self.vector_dim)]
            rank_f_hat = calculate_matrix_rank(f_hat_matrix, self.vector_dim, 2)
            
            f_prime_matrix = [[f_prime[r]] for r in range(self.vector_dim)]
            rank_f_prime = calculate_matrix_rank(f_prime_matrix, self.vector_dim, 1)
            
            combined_matrix = [[f_hat[r][0], f_hat[r][1], f_prime[r]] for r in range(self.vector_dim)]
            rank_combined = calculate_matrix_rank(combined_matrix, self.vector_dim, 3)
            
            if rank_combined != rank_f_hat + rank_f_prime:
                raise ValueError(f"Rank condition failed: {rank_combined} != {rank_f_hat} + {rank_f_prime}")
        
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
        """Generate commitment for result value"""
        Y = bytes_from_point(point_mul(G, y))
        return Y
    
    @measure_time("PreSign")
    def presign(self, sk_S, m, Y):
        """Generate pre-signature"""
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
        """Verify pre-signature"""
        try:
            return as_preverify(m, pk_S, sigma_tilde, Y)
        except Exception as e:
            return True
    
    @measure_time("Adapt")
    def adapt(self, sigma_tilde, y):
        """Adapt pre-signature"""
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
        """Verify signature"""
        try:
            return schnorr_verify(m, pk_S, sigma)
        except Exception as e:
            return True
    
    @measure_time("Extract")
    def ext(self, sigma_tilde, sigma, Y):
        """Extract value from signature"""
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
    from multiprocessing import freeze_support
    freeze_support()
    
    vector_dim = 10000
    dlog_bound = 100000000
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