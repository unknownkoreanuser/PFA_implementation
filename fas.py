import time
import random
import hashlib
from typing import Dict, Tuple, Any, List, Optional

from adaptors import as_presign, as_preverify, as_adapt, as_extract
from ipfe import ipfe_setup, ipfe_kgen, ipfe_enc, ipfe_dec_offline, ipfe_dec_online, ipfe_pubkgen
from utils import bytes_from_int, int_from_bytes, bytes_from_point, point_from_bytes, G, n, point_mul, point_add, is_point_on_curve, compute_discrete_log
from schnorr import schnorr_verify, schnorr_sign
import settings

settings.init()

# NIZK system implementation
class NIZK:
    @staticmethod
    def setup(security_param):
        """Generate common reference string for zero-knowledge proof system"""
        H = point_mul(G, int(hashlib.sha256(b"NIZK_FAS_H").hexdigest(), 16) % n)
        
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
    def _hash_challenge(*args, prefix=""):
        """Generate challenge hash for Fiat-Shamir transformation"""
        challenge_str = prefix
        for arg in args:
            challenge_str += str(arg)
        
        return int(hashlib.sha256(challenge_str.encode()).hexdigest(), 16) % n
    
    @staticmethod
    def prove_adgen(X, pp, mpk, ct, r0, r1, x, crs):
        """
        Generate zero-knowledge proof for seller's advertisement
        stmt = (X, pp, mpk, ct), wit = (r0, r1, x)
        """
        # Select random blinding values
        r_x = random.randint(1, n-1)
        r_r0 = random.randint(1, n-1)
        r_r1 = random.randint(1, n-1)

        # Generate commitments
        C_x = NIZK._commit_vector(x, r_x, crs, "adgen-x-commit")
        C_r0 = NIZK._commit_vector({"r0": r0}, r_r0, crs, "adgen-r0-commit")
        C_r1 = NIZK._commit_vector({"r1": r1}, r_r1, crs, "adgen-r1-commit")

        # Generate challenge using Fiat-Shamir transformation
        challenge = NIZK._hash_challenge(C_x, C_r0, C_r1, X, pp, mpk, ct, crs, prefix="adgen")

        # Generate responses to the challenge
        z_x = {}
        for i in range(len(x)):
            z_x[i] = (x[i] + challenge * random.randint(1, n-1)) % n
            
        z_r0 = (r0 + challenge * random.randint(1, n-1)) % n
        z_r1 = (r1 + challenge * random.randint(1, n-1)) % n
        
        z_r_x = (r_x + challenge * random.randint(1, n-1)) % n
        z_r_r0 = (r_r0 + challenge * random.randint(1, n-1)) % n
        z_r_r1 = (r_r1 + challenge * random.randint(1, n-1)) % n
        
        # Create proof structure
        proof = {
            "C_x": C_x,
            "C_r0": C_r0,
            "C_r1": C_r1,
            "challenge": challenge,
            "z_x": z_x,
            "z_r0": z_r0,
            "z_r1": z_r1,
            "z_r_x": z_r_x,
            "z_r_r0": z_r_r0,
            "z_r_r1": z_r_r1
        }

        # Serialize the proof
        serialized_proof = hashlib.sha256(str(proof).encode()).digest()
        
        return {
            "serialized": serialized_proof,
            "structured": proof
        }
    
    @staticmethod
    def verify_adgen(X, pp, mpk, ct, proof, crs):
        """Verify seller's advertisement proof"""
        try:
            structured_proof = None
            if isinstance(proof, dict) and "structured" in proof:
                structured_proof = proof["structured"]
                serialized_proof = proof["serialized"]
            else:
                # In a real implementation, more complex deserialization logic would be needed
                serialized_proof = proof
                structured_proof = {
                    "C_x": serialized_proof,
                    "C_r0": serialized_proof,
                    "C_r1": serialized_proof,
                    "challenge": int.from_bytes(serialized_proof[:4], byteorder="big") % n,
                    "z_x": {0: int.from_bytes(serialized_proof[4:8], byteorder="big") % n},
                    "z_r0": int.from_bytes(serialized_proof[8:12], byteorder="big") % n,
                    "z_r1": int.from_bytes(serialized_proof[12:16], byteorder="big") % n,
                    "z_r_x": int.from_bytes(serialized_proof[16:20], byteorder="big") % n,
                    "z_r_r0": int.from_bytes(serialized_proof[20:24], byteorder="big") % n,
                    "z_r_r1": int.from_bytes(serialized_proof[24:28], byteorder="big") % n
                }
            
            C_x = structured_proof.get("C_x")
            C_r0 = structured_proof.get("C_r0")
            C_r1 = structured_proof.get("C_r1")
            challenge = structured_proof.get("challenge")
            z_x = structured_proof.get("z_x")
            z_r0 = structured_proof.get("z_r0")
            z_r1 = structured_proof.get("z_r1")
            z_r_x = structured_proof.get("z_r_x")
            z_r_r0 = structured_proof.get("z_r_r0")
            z_r_r1 = structured_proof.get("z_r_r1")
            
            if any(comp is None for comp in [C_x, C_r0, C_r1, challenge, z_x, z_r0, z_r1, z_r_x, z_r_r0, z_r_r1]):
                return False
            
            # Verify challenge
            expected_challenge = NIZK._hash_challenge(C_x, C_r0, C_r1, X, pp, mpk, ct, crs, prefix="adgen")
            if challenge != expected_challenge:
                return False
            
            # Verify responses (in a real implementation, more verification logic would be needed)
            if isinstance(z_x, dict):
                for i in z_x:
                    if not isinstance(z_x[i], int):
                        return False
            else:
                return False
            
            return True
            
        except Exception as e:
            return False
    
    @staticmethod
    def prove_aux(t, y, fy_t, mpk, crs):
        """
        Generate proof for auxiliary information
        """
        # Select random blinding values
        r_t = random.randint(1, n-1)
        r_y = random.randint(1, n-1)

        # Generate commitments
        C_t = NIZK._commit_vector(t, r_t, crs, "aux-t-commit")
        C_y = NIZK._commit_vector(y, r_y, crs, "aux-y-commit")

        # Generate challenge using Fiat-Shamir transformation
        challenge = NIZK._hash_challenge(C_t, C_y, fy_t, mpk, crs, prefix="aux")

        # Generate responses to the challenge
        z_t = {}
        for i in range(len(t)):
            z_t[i] = (t[i] + challenge * random.randint(1, n-1)) % n
            
        z_y = {}
        for i in range(len(y)):
            z_y[i] = (y[i] + challenge * random.randint(1, n-1)) % n
        
        z_r_t = (r_t + challenge * random.randint(1, n-1)) % n
        z_r_y = (r_y + challenge * random.randint(1, n-1)) % n
        
        # Create proof structure
        proof = {
            "C_t": C_t,
            "C_y": C_y,
            "challenge": challenge,
            "z_t": z_t,
            "z_y": z_y,
            "z_r_t": z_r_t,
            "z_r_y": z_r_y
        }

        # Serialize the proof
        serialized_proof = hashlib.sha256(str(proof).encode()).digest()
        
        return {
            "serialized": serialized_proof,
            "structured": proof
        }
    
    @staticmethod
    def verify_aux(y, fy_t, mpk, proof, crs):
        """Verify auxiliary information proof"""
        try:
            # In a real implementation, more verification logic would be needed
            # Here we only perform basic verification
            
            return True
            
        except Exception as e:
            return False

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

class FunctionalAdaptorSignatures:
    def __init__(self, security_param=128, vector_dim=10, bound=1000000, input_range=100, func_range=100):
        self.security_param = security_param
        self.vector_dim = vector_dim
        self.bound = bound
        self.input_range = input_range
        self.func_range = func_range
        self.times = {}
    
    @measure_time("Setup")
    def setup(self):
        """
        Setup(1λ):
        1: Sample crs ← NIZK.Setup(1λ)
        2: Sample pp′ ← IPFE.Gen(1λ)
        3: ret pp := (crs, pp′)
        """
        # Generate CRS for NIZK system
        nizk_crs = NIZK.setup(self.security_param)
        
        # Generate IPFE parameters
        ipfe_pp = self.ipfe_gen(self.security_param)
        
        crs = {"security_param": self.security_param, "nizk": nizk_crs}
        pp = {"security_param": self.security_param, "ipfe": ipfe_pp}
        
        return crs, pp
    
    def ipfe_gen(self, security_param):
        """Generate IPFE parameters"""
        return {"security_param": security_param}
    
    @measure_time("AdGen")
    def adgen(self, pp, X, x):
        """
        AdGen(pp, X, x):
        1: Sample random coins r0, r1
        2: Let (mpk, msk) := IPFE.Setup(pp′, 1ℓ+1; r0)
        3: Sample t ←$ Zℓp, let xe := (xT, 0)T ∈ Zℓ+1p
        4: Let ct := IPFE.Enc(mpk, xe; r1)
        5: Let stmt := (X, pp′, mpk, ct), wit := (r0, r1, x)
        6: Let π ← NIZK.Prove(crs, stmt, wit)
        7: ret advt := (mpk, ct, π), st := (msk, t)
        """
        # Sample random values
        r0 = random.randint(1, n-1)
        r1 = random.randint(1, n-1)
        
        # Generate IPFE master keys
        mpk, msk = ipfe_setup(self.vector_dim + 1)
        
        # Sample random vector t
        t = {}
        for i in range(self.vector_dim):
            t[i] = random.randint(1, n-1)
        
        # Create extended vector xe = (x^T, 0)^T
        ex = {}
        for i in range(self.vector_dim):
            ex[i] = x[i]
        ex[self.vector_dim] = 0
        
        # Encrypt
        ct0, ct1 = ipfe_enc(self.vector_dim + 1, mpk, ex)
        ct = {"ct0": ct0, "ct1": ct1}
        
        # Generate zero-knowledge proof
        if hasattr(self, 'current_crs'):
            crs = self.current_crs
            proof = NIZK.prove_adgen(X, pp["ipfe"], mpk, ct, r0, r1, x, crs["nizk"])
        else:
            # Temporary hash-based proof (real implementation would need ZK proof)
            proof = hashlib.sha256(str(X).encode() + str(x).encode()).digest()
            proof = {"serialized": proof}
        
        advt = {"mpk": mpk, "ct": ct, "proof": proof}
        st = {"msk": msk, "t": t, "x": x}
        
        return advt, st
    
    @measure_time("AdVerify")
    def adverify(self, pp, X, advt):
        """
        AdVerify(pp, X, advt):
        1: ret NIZK.Vf(crs, (X, pp′, mpk, ct), π)
        """
        mpk = advt["mpk"]
        ct = advt["ct"]
        proof = advt["proof"]
        
        if hasattr(self, 'current_crs'):
            crs = self.current_crs
            return NIZK.verify_adgen(X, pp["ipfe"], mpk, ct, proof, crs["nizk"])
        
        # Temporary implementation (always returns True)
        return True
    
    @measure_time("AuxGen")
    def auxgen(self, advt, st, y):
        """
        AuxGen(advt, st, y):
        1: Parse advt = (mpk, ct, π), st = (msk, t)
        2: Let ye := (yT, fy(t))T ∈ Zℓ+1p
        3: Let pky := IPFE.PubKGen(mpk, ye)
        4: ret auxy := pky, πy := fy(t)
        """
        mpk = advt["mpk"]
        msk = st["msk"]
        t = st["t"]
        
        # Calculate fy(t) = <y, t>
        fy_t = 0
        for i in range(self.vector_dim):
            fy_t = (fy_t + (y[i] * t[i]) % n) % n
        
        # Create extended vector ye = (y^T, fy(t))^T
        ey = {}
        for i in range(self.vector_dim):
            ey[i] = y[i]
        ey[self.vector_dim] = fy_t
        
        # Generate public key
        pky = ipfe_pubkgen(self.vector_dim + 1, mpk, ey)
        
        # Additional: Generate proof for auxiliary information
        if hasattr(self, 'current_crs'):
            crs = self.current_crs
            aux_proof = NIZK.prove_aux(t, y, fy_t, mpk, crs["nizk"])
            # In a real implementation, this proof would be returned and verified
        
        return pky, fy_t
    
    @measure_time("AuxVerify")
    def auxverify(self, advt, y, auxy, pi_y):
        """
        AuxVerify(advt, y, auxy, πy):
        1: Parse advt = (mpk, ct, π), let ye := (yT, πy)T
        2: ret 1 iff auxy = IPFE.PubKGen(mpk, ye)
        """
        mpk = advt["mpk"]
        
        # Create extended vector ye = (y^T, pi_y)^T
        ey = {}
        for i in range(self.vector_dim):
            ey[i] = y[i]
        ey[self.vector_dim] = pi_y
        
        # Calculate expected public key
        expected_auxy = ipfe_pubkgen(self.vector_dim + 1, mpk, ey)
        
        # Check if keys match
        return auxy == expected_auxy
    
    @measure_time("FPreSign")
    def fpresign(self, advt, sk, m, X, y, auxy):
        """
        FPreSign(advt, sk, m, X, y, auxy):
        1: ret σe ← AS.PreSign(sk, m, auxy)
        """
        # Generate adaptor pre-signature
        sigma_tilde = as_presign(m, sk, bytes_from_int(random.randint(1, n-1)), auxy)
        return sigma_tilde
    
    @measure_time("FPreVerify")
    def fpreverify(self, advt, vk, m, X, y, auxy, pi_y, sigma_tilde):
        """
        FPreVerify(advt, vk, m, X, y, auxy, πy, σe):
        1: ret AuxVerify(advt, y, auxy, πy) ∧ AS.PreVerify(vk, m, auxy, σe)
        """
        # Verify auxiliary information and pre-signature
        if not self.auxverify(advt, y, auxy, pi_y):
            return False
        
        return as_preverify(m, vk, sigma_tilde, auxy)
    
    @measure_time("Adapt")
    def adapt(self, advt, st, vk, m, X, x, y, auxy, sigma_tilde):
        """
        Adapt(advt, st, vk, m, X, x, y, auxy, σe):
        1: Parse advt = (mpk, ct, π), st = (msk, t)
        2: Let ye := (yT, fy(t))T
        3: Let sky := IPFE.KGen(msk, ye)
        4: ret σ := AS.Adapt(vk, m, auxy, sky, σe)
        """
        mpk = advt["mpk"]
        msk = st["msk"]
        t = st["t"]
        
        # Calculate fy(t) = <y, t>
        fy_t = 0
        for i in range(self.vector_dim):
            fy_t = (fy_t + (y[i] * t[i]) % n) % n
        
        # Create extended vector ye = (y^T, fy(t))^T
        ey = {}
        for i in range(self.vector_dim):
            ey[i] = y[i]
        ey[self.vector_dim] = fy_t
        
        # Generate function secret key
        sky = ipfe_kgen(self.vector_dim + 1, msk, ey)
        
        # Adapt signature
        sigma = as_adapt(m, vk, sigma_tilde, auxy, sky)
        
        return sigma
    
    @measure_time("FExt")
    def fext(self, advt, sigma_tilde, sigma, X, y, auxy, m, vk, pi_y):
        """
        FExt(advt, σe, σ, X, y, auxy):
        1: Parse advt = (mpk, ct, π).
        2: Let z := AS.Ext(σe, σ, auxy)
        3: ret v := IPFE.Dec(z, ct)
        """
        # Extract function secret key from signature
        sky = as_extract(m, vk, sigma_tilde, sigma, auxy)
        
        # Parse ciphertext
        ct = advt["ct"]
        ct0 = ct["ct0"]
        ct1 = ct["ct1"]
        
        # Create extended vector ye = (y^T, pi_y)^T
        y_elongated = {}
        for i in range(self.vector_dim):
            y_elongated[i] = y[i]
        y_elongated[self.vector_dim] = pi_y
        
        # Prepare for offline decryption
        ct2 = ipfe_dec_offline(self.vector_dim + 1, y_elongated, ct1)
        
        # Calculate result with online decryption
        result = ipfe_dec_online(sky, ct0, ct2, self.bound)
        
        return result
    
    def run_protocol(self, use_fixed_seed=False, verbose=True):
        if use_fixed_seed:
            random.seed(42)
        else:
            current_time = int(time.time())
            random.seed(current_time)
        
        crs, pp = self.setup()
        self.current_crs = crs
        
        x = {}
        for i in range(self.vector_dim):
            x[i] = random.randint(1, self.input_range)
        
        X = bytes_from_point(point_mul(G, sum(x.values()) % n))
        
        advt, st = self.adgen(pp, X, x)
        
        ad_verified = self.adverify(pp, X, advt)
        if not ad_verified:
            return
        
        y = {}
        for i in range(self.vector_dim):
            y[i] = random.randint(1, self.func_range)
        
        auxy, pi_y = self.auxgen(advt, st, y)
        
        aux_verified = self.auxverify(advt, y, auxy, pi_y)
        if not aux_verified:
            return
        
        sk = bytes_from_int(random.randint(1, n-1))
        vk = bytes_from_point(point_mul(G, int_from_bytes(sk)))
        
        m = b'test_payment_transaction'
        
        sigma_tilde = self.fpresign(advt, sk, m, X, y, auxy)
        
        pre_verified = self.fpreverify(advt, vk, m, X, y, auxy, pi_y, sigma_tilde)
        if not pre_verified:
            return
        
        sigma = self.adapt(advt, st, vk, m, X, x, y, auxy, sigma_tilde)
        
        sig_verified = schnorr_verify(m, vk, sigma)
        if not sig_verified:
            return
        
        result = self.fext(advt, sigma_tilde, sigma, X, y, auxy, m, vk, pi_y)
        
        expected = 0
        for i in range(self.vector_dim):
            expected = (expected + (x[i] * y[i]) % n) % n
        
        print(f"Function evaluation result: {result}")
        print(f"Expected inner product: {expected}")
        
        if result == expected:
            print("✓ Results match! The protocol computed the correct inner product.")
        else:
            print("✗ Results do not match! There's an issue with the protocol computation.")
        
        print("\nExecution times:")
        for step, time_taken in self.times.items():
            print(f"{step.ljust(10)}: {time_taken:.6f} seconds")
        print(f"Total: {sum(self.times.values()):.6f} seconds")
        
        return result == expected

if __name__ == "__main__":
    # Configuration parameters
    vector_dim = 1000        # Vector dimension
    dlog_bound = 10000000      # Discrete log calculation bound
    input_range = 100           # Input value range (1 to input_range)
    func_range = 100            # Function value range (1 to func_range)
    use_fixed_seed = False      # Set to True for reproducible testing
    
    fas = FunctionalAdaptorSignatures(
        security_param=128,
        vector_dim=vector_dim,
        bound=dlog_bound,
        input_range=input_range,
        func_range=func_range
    )
    fas.run_protocol(use_fixed_seed)