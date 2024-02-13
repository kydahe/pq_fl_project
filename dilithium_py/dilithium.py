import os
import time

from dilithium_py.polynomials import *
from dilithium_py.modules import *
from dilithium_py.shake_wrapper import Shake128, Shake256
from dilithium_py.utils import *
from dilithium_py.ntt_helper import NTTHelperDilithium

from multiprocessing import Process, Queue, cpu_count, Value, Lock

try:
    from aes256_ctr_drbg import AES256_CTR_DRBG
except ImportError as e:
    print("Error importing AES256 CTR DRBG. Have you tried installing requirements?")
    print(f"ImportError: {e}\n")
    print("Dilithium will work perfectly fine with system randomness")
    
DEFAULT_PARAMETERS = {
    "dilithium2" : {
        "n" : 256,
        "q" : 8380417,
        "d" : 13,
        "k" : 4,
        "l" : 4,
        "eta" : 2,
        "eta_bound" : 15,
        "tau" : 39,
        "omega" : 80,
        "gamma_1" : 131072, # 2^17
        "gamma_2" : 95232,  # (q-1)/88
    },
    
    "dilithium3" : {
        "n" : 256,
        "q" : 8380417,
        "d" : 13,
        "k" : 6,
        "l" : 5,
        "eta" : 4,
        "eta_bound" : 9,
        "tau" : 49,
        "omega" : 55,
        "gamma_1" : 524288, # 2^19
        "gamma_2" : 261888, # (q-1)/88
    },
    "dilithium4" : {
        "n" : 256,
        "q" : 8380417,
        "d" : 13,
        "k" : 1,
        "l" : 7,
        "eta" : 4,
        "eta_bound" : 9,
        "tau" : 49,
        "omega" : 55,
        "gamma_1" : 524288, # 2^19
        "gamma_2" : 261888, # (q-1)/88
    },
    "dilithium5" : {
        "n" : 256,
        "q" : 8380417,
        "d" : 13,
        "k" : 8,
        "l" : 7,
        "eta" : 2,
        "eta_bound" : 15,
        "tau" : 60,
        "omega" : 75,
        "gamma_1" : 524288, # 2^19
        "gamma_2" : 261888, # (q-1)/88
    },
}

class Dilithium:
    def __init__(self, parameter_set):
        self.n   = parameter_set["n"]
        self.q   = parameter_set["q"]
        self.d   = parameter_set["d"]
        self.k   = parameter_set["k"]
        self.l   = parameter_set["l"]
        self.eta = parameter_set["eta"]
        self.eta_bound = parameter_set["eta_bound"]
        self.tau = parameter_set["tau"]
        self.omega = parameter_set["omega"]
        self.gamma_1 = parameter_set["gamma_1"]
        self.gamma_2 = parameter_set["gamma_2"]
        self.beta    = self.tau * self.eta
        
        self.R = PolynomialRing(self.q, self.n, ntt_helper=NTTHelperDilithium)
        self.M = Module(self.R)
        
        self.drbg = None
        self.random_bytes = os.urandom

        self.sk_params = {}
    
    """
    The following two methods allow us to use deterministic
    randomness throughout all of Dilithium. This is helpful
    for the KAT tests more than anything!
    """
    def set_drbg_seed(self, seed):
        """
        Setting the seed switches the entropy source
        from os.urandom to AES256 CTR DRBG
            
        Note: requires pycryptodome for AES impl.
        (Seemed overkill to code my own AES for Kyber)
        """
        self.drbg = AES256_CTR_DRBG(seed)
        self.random_bytes = self.drbg.random_bytes
        
    def reseed_drbg(self, seed):
        """
        Reseeds the DRBG, errors if a DRBG is not set.
        
        Note: requires pycryptodome for AES impl.
        (Seemed overkill to code my own AES for Kyber)
        """
        if self.drbg is None:
            raise Warning(f"Cannot reseed DRBG without first initialising. Try using `set_drbg_seed`")
        else:
            self.drbg.reseed(seed)
            
    """
    H() uses Shake256 to hash data to 32 and 64 bytes in a 
    few places in the code 
    """
    @staticmethod  
    def _h(input_bytes, length):
        """
        H: B^*  -> B^*
        """
        return Shake256.digest(input_bytes, length)
            
    """
    Figure 3 (Supporting algorithms for Dilithium)
    `_make_hint/_use_hint` is applied to matricies and `_make_hint_poly/_use_hint_poly` 
    applies to the polynomials, which are elements of the matricies. 
    
    `_make_hint_poly/_use_hint_poly` uses the util functions `use_hint/make_hint` 
    which works on field elements (see utils.py)
    
        https://pq-crystals.org/dilithium/data/dilithium-specification-round3-20210208.pdf
    """  
    def _make_hint(self, v1, v2, alpha):
        matrix = [[self._make_hint_poly(p1, p2, alpha) for p1, p2 in zip(v1.rows[i], v2.rows[i])]
                   for i in range(v1.m)] 
        return self.M(matrix)
        
    def _use_hint(self, v1, v2, alpha):
        matrix = [[self._use_hint_poly(p1, p2, alpha) for p1, p2 in zip(v1.rows[i], v2.rows[i])]
                  for i in range(v1.m)]
        return self.M(matrix)
    
    def _make_hint_poly(self, p1, p2, alpha):
        coeffs = [make_hint(r, z, alpha, self.q) for r, z in zip(p1.coeffs, p2.coeffs)]
        return self.R(coeffs)
        
    def _use_hint_poly(self, p1, p2, alpha, is_ntt=False):
        coeffs = [use_hint(h, r, alpha, self.q) for h, r in zip(p1.coeffs, p2.coeffs)]
        return self.R(coeffs)

    @staticmethod
    def _sum_hint(hint):
        """
        Helper function to count the number of coeffs == 1
        in all the polynomials of a matrix
        """
        return sum(c for row in hint.rows for p in row for c in p)

    def _sample_in_ball(self, seed, is_ntt=False):
        """
        Figure 2 (Sample in Ball)        
            https://pq-crystals.org/dilithium/data/dilithium-specification-round3-20210208.pdf

        Create a random 256-element array with τ ±1’s and (256 − τ) 0′s using 
        the input seed ρ (and an SHAKE256) to generate the randomness needed
        """        
        def rejection_sample(i, xof):
            """
            Sample random bytes from `xof_bytes` and
            interpret them as integers in {0, ..., 255}
            
            Rejects values until a value j <= i is found
            """
            while True:
                j = xof.read(1)
                j = int.from_bytes(j, "little")
                if j <= i: 
                    return j
        
        # Initialise the XOF
        Shake256.absorb(seed)
        
        # Set the first 8 bytes for the sign, and leave the rest for
        # sampling.
        sign_bytes = Shake256.read(8)
        sign_int = int.from_bytes(sign_bytes, "little")
        
        # Set the list of coeffs to be 0
        coeffs = [0 for _ in range(self.n)]
        
        # Now set tau values of coeffs to be ±1
        for i in range(256 - self.tau, self.n):
            j = rejection_sample(i, Shake256)
            coeffs[i] = coeffs[j]
            coeffs[j] = 1 - 2*(sign_int & 1)
            sign_int >>= 1
            
        return self.R(coeffs, is_ntt=is_ntt)
        
    def _sample_error_polynomial(self, rho_prime, i, is_ntt=False):
        def rejection_sample(xof):
            """
            Sample a random byte from `xof_bytes` and
            interpret it as two integers in {0, ..., 2η}
            by considering the top and bottom four bits
            
            Rejects values until a value j < 2η is found
            """
            while True:
                js = []

                # Consider two values for each byte (top and bottom four bits)
                j  = xof.read(1)
                j  = int.from_bytes(j, "little")
                j0 = j & 0x0F
                j1 = j >> 4
                
                # rejection sample
                if j0 < self.eta_bound:
                    if self.eta == 2: j0 %= 5
                    js.append(self.eta - j0)
                    
                if j1 < self.eta_bound:
                    if self.eta == 2: j1 %= 5
                    js.append(self.eta - j1)
                
                if js:
                    return js
                    
        # Initialise the XOF
        seed = rho_prime + int.to_bytes(i, 2, "little")
        Shake256.absorb(seed)
    
        # Sample bytes for all n coeffs
        # TODO: make this better.
        coeffs = []
        while len(coeffs) < self.n:
            js = rejection_sample(Shake256)
            coeffs += js

        # Remove the last byte if we ended up overfilling
        if len(coeffs) > self.n:
            coeffs = coeffs[:self.n]
        
        return self.R(coeffs, is_ntt=is_ntt)
    
    def _sample_matrix_polynomial(self, rho, i, j, is_ntt=False):
        def rejection_sample(xof):
            """
            Sample three random bytes from `xof` and
            interpret them as integers in {0, ..., 2^23 - 1}
            
            Rejects values until a value j < q is found
            """
            while True:                
                j_bytes = xof.read(3)
                j = int.from_bytes(j_bytes, "little")
                j &= 0x7FFFFF
                if j < self.q:
                    return j

        # Initialise the XOF
        seed = rho + bytes([j, i])
        Shake128.absorb(seed)
        coeffs = [rejection_sample(Shake128) for _ in range(self.n)]
        return self.R(coeffs, is_ntt=is_ntt)
    
    def _sample_mask_polynomial(self, rho_prime, i, kappa, is_ntt=False):                            
        if self.gamma_1 == (1 << 17):
            bit_count = 18
            total_bytes = 576 # (256 * 18) / 8
        else:
            bit_count = 20
            total_bytes = 640 # (256 * 20) / 8
        
        # Initialise the XOF
        seed = rho_prime + int.to_bytes(kappa+i, 2, "little")
        xof_bytes = Shake256.digest(seed, total_bytes)
        r = int.from_bytes(xof_bytes, 'little')
        mask = (1 << bit_count) - 1
        coeffs = [self.gamma_1 - ((r >> bit_count*i) & mask) for i in range(self.n)]
        
        return self.R(coeffs, is_ntt=is_ntt)
        
    def _expandA(self, rho, is_ntt=False):
        """
        Helper function which generates a element of size
        k x l from a seed `rho`.
        
        When `transpose` is set to True, the matrix A is
        built as the transpose.
        """
        matrix = [[self._sample_matrix_polynomial(rho, i, j, is_ntt=is_ntt)
                   for j in range(self.l)]
                   for i in range(self.k)]
        return self.M(matrix)
        
    def _expandS(self, rho_prime, is_ntt=False):
        s1_elements = [self._sample_error_polynomial(rho_prime, i, is_ntt=is_ntt) 
                       for i in range(self.l)]
        s2_elements = [self._sample_error_polynomial(rho_prime, i, is_ntt=is_ntt) 
                       for i in range(self.l, self.l+self.k)]
            
        s1 = self.M(s1_elements).transpose()
        s2 = self.M(s2_elements).transpose()
        return s1, s2
        
    def _expandMask(self, rho_prime, kappa, is_ntt=False):
        elements = [self._sample_mask_polynomial(rho_prime, i, kappa, is_ntt=is_ntt)
                    for i in range(self.l)]
        return self.M(elements).transpose()
    
    @staticmethod
    def _pack_pk(rho, t1):
        return rho + t1.bit_pack_t1()
        
    def _pack_sk(self, rho, K, tr, s1, s2, t0):
        s1_bytes = s1.bit_pack_s(self.eta)
        s2_bytes = s2.bit_pack_s(self.eta)
        t0_bytes = t0.bit_pack_t0()
        return rho + K + tr + s1_bytes + s2_bytes + t0_bytes
    
    def _pack_h(self, h):
        non_zero_positions = [[i for i,c in enumerate(poly.coeffs) if c == 1]
                               for row in h.rows for poly in row]
        packed  = []
        offsets = []
        for positions in non_zero_positions:
            packed.extend(positions)
            offsets.append(len(packed))

        padding_len = (self.omega - offsets[-1])
        packed.extend([0 for _ in range(padding_len)])
        return bytes(packed + offsets)
        
    def _pack_sig(self, c_tilde, z, h):
        return c_tilde + z.bit_pack_z(self.gamma_1) + self._pack_h(h)
        
    def _unpack_pk(self, pk_bytes):
        rho, t1_bytes = pk_bytes[:32],  pk_bytes[32:]
        t1 = self.M.bit_unpack_t1(t1_bytes, self.k, 1)
        return rho, t1
    
    def _unpack_sk(self, sk_bytes):
        if self.eta == 2:
            s_bytes = 96
        else:
            s_bytes = 128
        s1_len = s_bytes * self.l
        s2_len = s_bytes * self.k
        t0_len = 416 * self.k
        # 544 * k + 128 * l + 96 = 
        # 11.25 = 4.25 k + l
        if len(sk_bytes) != 3*32 + s1_len + s2_len + t0_len:
            raise ValueError("SK packed bytes is of the wrong length")
        
        # Split bytes between seeds and vectors
        sk_seed_bytes, sk_vec_bytes = sk_bytes[:96], sk_bytes[96:]
        
        # Unpack seed bytes
        rho, K, tr = sk_seed_bytes[:32], sk_seed_bytes[32:64], sk_seed_bytes[64:96]
        
        # Unpack vector bytes
        s1_bytes = sk_vec_bytes[:s1_len]
        s2_bytes = sk_vec_bytes[s1_len:s1_len+s2_len]
        t0_bytes = sk_vec_bytes[-t0_len:]
        
        # Unpack bytes to vectors
        s1 = self.M.bit_unpack_s(s1_bytes, self.l, 1, self.eta)
        s2 = self.M.bit_unpack_s(s2_bytes, self.k, 1, self.eta)
        t0 = self.M.bit_unpack_t0(t0_bytes, self.k, 1)
        
        return rho, K, tr, s1, s2, t0
    
    def _unpack_h(self, h_bytes):
        offsets = [0] + list(h_bytes[-self.k:])
        non_zero_positions = [list(h_bytes[offsets[i]:offsets[i+1]]) for i in range(self.k)]
        
        matrix = []
        for poly_non_zero in non_zero_positions:
            coeffs = [0 for _ in range(self.n)]
            for non_zero in poly_non_zero:
                coeffs[non_zero] = 1
            matrix.append([self.R(coeffs)])
        return self.M(matrix)
        
    def _unpack_sig(self, sig_bytes):
        c_tilde = sig_bytes[:32]
        z_bytes = sig_bytes[32: -(self.k + self.omega)]
        h_bytes = sig_bytes[-(self.k + self.omega):]
        
        z = self.M.bit_unpack_z(z_bytes, self.l, 1, self.gamma_1)
        h = self._unpack_h(h_bytes)
        return c_tilde, z, h
        
    def keygen(self):
        # Random seed
        zeta = self.random_bytes(32)
        
        # Expand with an XOF (SHAKE256)
        seed_bytes = self._h(zeta, 128)
        
        # Split bytes into suitible chunks
        rho, rho_prime, K = seed_bytes[:32], seed_bytes[32:96], seed_bytes[96:]
                
        # Generate matrix A ∈ R^(kxl)
        A = self._expandA(rho, is_ntt=True)
        
        # Generate the error vectors s1 ∈ R^l, s2 ∈ R^k
        s1, s2 = self._expandS(rho_prime)        
        s1_hat = s1.copy_to_ntt()

        # Matrix multiplication
        t = (A @ s1_hat).from_ntt() + s2
        
        t1, t0 = t.power_2_round(self.d)
        
        # Pack up the bytes
        pk = self._pack_pk(rho, t1)
        tr = self._h(pk, 32)
                
        sk = self._pack_sk(rho, K, tr, s1, s2, t0)
        return pk, sk

    # Added by Yiwei: precomputing with multiprocessing
    # Pre compute before calculating the signature
    def get_one_param(self, sk_bytes, s_kappa, e_kappa, shared_queues, rho_prime, A, alpha, gamma_2):
        kappa = s_kappa
        results = []
        while kappa < e_kappa:
            y = self._expandMask(rho_prime, kappa)
            y_hat = y.copy_to_ntt()
            kappa += self.l # + 4
            w  = (A @ y_hat).from_ntt()
            w1, w0 = w.decompose(alpha)
            w1_bytes = w1.bit_pack_w(self.gamma_2)
            # print(i)
            if (w0, w1, w1_bytes, y) not in results:
                results.append((w0, w1, w1_bytes, y, kappa))
        shared_queues.put(results)
        
    def precomputing(self, sk_bytes, N=100):
        if sk_bytes not in self.sk_params:
            self.sk_params[sk_bytes] = {}
            self.sk_params[sk_bytes]['precomputed'] = []
        
        rho, K, tr, s1, s2, t0 = self._unpack_sk(sk_bytes)
        A = self._expandA(rho, is_ntt=True)
        u = self._h(tr, 64)
        kappa = 0
        rho_prime = self._h(K + u, 64)
        alpha = self.gamma_2 << 1
        i = 0
        s1.to_ntt()
        s2.to_ntt()
        t0.to_ntt()
        self.sk_params[sk_bytes]['rho'] = rho
        self.sk_params[sk_bytes]['K'] = K
        self.sk_params[sk_bytes]['tr'] = tr
        self.sk_params[sk_bytes]['s1'] = s1
        self.sk_params[sk_bytes]['s2'] = s2
        self.sk_params[sk_bytes]['t0'] = t0
        
        num_processes = cpu_count()
        shared_queues = Queue()
        processes = []
        kappa_range = N // num_processes
        
        
        for i in range(num_processes):
            s_kappa = i * kappa_range * self.l
            e_kappa = (i+1) * kappa_range * self.l if i < num_processes - 1 else N * self.l
            p = Process(target=self.get_one_param, args=(sk_bytes, s_kappa, e_kappa, shared_queues, rho_prime, A, alpha, self.gamma_2))
            processes.append(p)
            p.start()
            if e_kappa == N * self.l:
                break
        
        for p in processes:
            self.sk_params[sk_bytes]['precomputed'].extend(shared_queues.get())
        
        for p in processes:
            p.join()

        # print(len(self.sk_params[sk_bytes]['precomputed']))

    def find_sign(self, shared_queues, terminate_flag, lock, precomputed_params, m, mu, s1, s2, t0, alpha):
        results = []
        # print(len(precomputed_params))
        is_found = False
        if terminate_flag.value == 1:
            return
        for i in range(len(precomputed_params)):
            w0, w1, w1_bytes, y, kappa = precomputed_params[i]
                
            w1_bytes_tilde = self._h(m + w1_bytes, 64)
            
            c_tilde = self._h(mu + w1_bytes_tilde, 32)
            c = self._sample_in_ball(c_tilde)
            c.to_ntt()
            z = y + s1.scale(c).from_ntt()
            if z.check_norm_bound(self.gamma_1 - self.beta):
                continue
            
            w0_minus_cs2 = w0 - s2.scale(c).from_ntt()
            if w0_minus_cs2.check_norm_bound(self.gamma_2 - self.beta):
                continue
            
            c_t0 = t0.scale(c).from_ntt()
            # c_t0.reduce_coefficents()
            if c_t0.check_norm_bound(self.gamma_2):
                continue
            
            w0_minus_cs2_plus_ct0 = w0_minus_cs2 + c_t0
            h = self._make_hint(w0_minus_cs2_plus_ct0, w1, alpha)            
            if self._sum_hint(h) > self.omega:
                continue
            
            # self.sk_params[sk_bytes]['precomputed'].remove((w0, w1, w1_bytes, y, kappa))
            
            sig = self._pack_sig(c_tilde, z, h)
            # print("find sign")
            results.append((sig, w0, w1, w1_bytes, y, kappa))
            is_found = True
            break

        shared_queues.put(results)
        if is_found == True:
            with lock:
                if terminate_flag.value == 0:
                    terminate_flag.value = 1 
        

    def sign_precomputed(self, sk_bytes, m, N=50, start=0):
        # rho, K, tr, s1, s2, t0 = self._unpack_sk(sk_bytes)
        rho = self.sk_params[sk_bytes]['rho'] 
        K = self.sk_params[sk_bytes]['K']
        tr = self.sk_params[sk_bytes]['tr']
        s1 = self.sk_params[sk_bytes]['s1']
        s2 = self.sk_params[sk_bytes]['s2']
        t0 = self.sk_params[sk_bytes]['t0'] 
        mu = self._h(tr + m, 64) 
        # s1.to_ntt()
        # s2.to_ntt()
        # t0.to_ntt()
        alpha = self.gamma_2 << 1
        if sk_bytes in self.sk_params:
            precomputed_params = self.sk_params[sk_bytes]['precomputed'][start: start + N] # w0, w1, w1_bytes, y, kappa
            
            is_calc = False
            num_processes = cpu_count()
            shared_queues = Queue()
            terminate_flag = Value('i', 0)
            lock = Lock()
            processes = []
            cases_per_process = N // num_processes + 1
            for i in range(num_processes):
                params = precomputed_params[i*cases_per_process : (i+1)*cases_per_process] if (i+1)*cases_per_process <= N else precomputed_params[i*cases_per_process : N]
                p = Process(target=self.find_sign, args=(shared_queues, terminate_flag, lock, params, m, mu, s1, s2, t0, alpha))
                processes.append(p)
                p.start()
                if (i+1)*cases_per_process >= N:
                    break
            
            # for p in processes:
            while not shared_queues.empty():
                res = shared_queues.get()
                if is_calc == False and len(res) > 0:
                    # print("res > 0")
                    (sig, w0, w1, w1_bytes, y, kappa) = res[0]
                    is_calc = True
                    break
            
            if is_calc == True:
                for p in processes:
                    p.terminate()
                    # p.join()
            
            if is_calc:
                # print("is_calc = true")
                self.sk_params[sk_bytes]['precomputed'].remove((w0, w1, w1_bytes, y, kappa))
                return sig, 0, y
            
        A = self._expandA(rho, is_ntt=True)
        u = self._h(tr, 64)
        pre_len = len(self.sk_params[sk_bytes]['precomputed'])
        if pre_len > 0:
            _, _, _, _, kappa = self.sk_params[sk_bytes]['precomputed'][pre_len - 1]
        else:
            kappa = 0
        rho_prime = self._h(K + u, 64)
        
        i = 0
        while True:
            i = i + 1
            y = self._expandMask(rho_prime, kappa)
            y_hat = y.copy_to_ntt()
            
            kappa += self.l
            
            w  = (A @ y_hat).from_ntt()
            w1, w0 = w.decompose(alpha)
            
            w1_bytes = w1.bit_pack_w(self.gamma_2) 

            if (w0, w1, w1_bytes, y) not in self.sk_params[sk_bytes]['precomputed']:
                self.sk_params[sk_bytes]['precomputed'].append((w0, w1, w1_bytes, y, kappa))
            
            w1_bytes_tilde = self._h(m + w1_bytes, 64)

            c_tilde = self._h(mu + w1_bytes_tilde, 32) 
            c = self._sample_in_ball(c_tilde)
            c.to_ntt()
            
            z = y + s1.scale(c).from_ntt() 
            if z.check_norm_bound(self.gamma_1 - self.beta):
                continue

            w0_minus_cs2 = w0 - s2.scale(c).from_ntt()
            if w0_minus_cs2.check_norm_bound(self.gamma_2 - self.beta): 
                continue
            
            c_t0 = t0.scale(c).from_ntt()
            # c_t0.reduce_coefficents()

            if c_t0.check_norm_bound(self.gamma_2):
                continue
            
            w0_minus_cs2_plus_ct0 = w0_minus_cs2 + c_t0
            
            h = self._make_hint(w0_minus_cs2_plus_ct0, w1, alpha)            

            if self._sum_hint(h) > self.omega:
                continue
            
            
            self.sk_params[sk_bytes]['precomputed'].remove((w0, w1, w1_bytes, y, kappa))
            return self._pack_sig(c_tilde, z, h), i, y
    

    # Added by Yiwei: only precomputing version without multiprocessing
    # Pre compute before calculating the signature
    def precomputing_only(self, sk_bytes, N=100):
        if sk_bytes not in self.sk_params:
            self.sk_params[sk_bytes] = {}
            self.sk_params[sk_bytes]['precomputed'] = []
        
        rho, K, tr, s1, s2, t0 = self._unpack_sk(sk_bytes)
        A = self._expandA(rho, is_ntt=True)
        u = self._h(tr, 64)
        kappa = 0
        rho_prime = self._h(K + u, 64)
        alpha = self.gamma_2 << 1
        i = 0
        s1.to_ntt()
        s2.to_ntt()
        t0.to_ntt()
        self.sk_params[sk_bytes]['rho'] = rho
        self.sk_params[sk_bytes]['K'] = K
        self.sk_params[sk_bytes]['tr'] = tr
        self.sk_params[sk_bytes]['s1'] = s1
        self.sk_params[sk_bytes]['s2'] = s2
        self.sk_params[sk_bytes]['t0'] = t0
        while len(self.sk_params[sk_bytes]['precomputed']) < N:
            i = i+1
            y = self._expandMask(rho_prime, kappa)
            y_hat = y.copy_to_ntt()
            kappa += self.l # + 4
            w  = (A @ y_hat).from_ntt()
            w1, w0 = w.decompose(alpha)
            w1_bytes = w1.bit_pack_w(self.gamma_2)
            # print(i)
            if (w0, w1, w1_bytes, y) not in self.sk_params[sk_bytes]['precomputed']:
                self.sk_params[sk_bytes]['precomputed'].append((w0, w1, w1_bytes, y, kappa))

            
    # Modified by Yiwei: only precomputing version without multiprocessing
    def sign_precomputed_only(self, sk_bytes, m, N=50, start=0):
        # rho, K, tr, s1, s2, t0 = self._unpack_sk(sk_bytes)
        rho = self.sk_params[sk_bytes]['rho'] 
        K = self.sk_params[sk_bytes]['K']
        tr = self.sk_params[sk_bytes]['tr']
        s1 = self.sk_params[sk_bytes]['s1']
        s2 = self.sk_params[sk_bytes]['s2']
        t0 = self.sk_params[sk_bytes]['t0'] 
        mu = self._h(tr + m, 64) 
        # s1.to_ntt()
        # s2.to_ntt()
        # t0.to_ntt()
        alpha = self.gamma_2 << 1
        if sk_bytes in self.sk_params:
            precomputed_params = self.sk_params[sk_bytes]['precomputed'] # w0, w1, w1_bytes, y, kappa
            for i in range(start, start + N):
            # for w0, w1, w1_bytes, y, kappa in precomputed_params:
                w0, w1, w1_bytes, y, kappa = precomputed_params[i]
                
                w1_bytes_tilde = self._h(m + w1_bytes, 64)
                
                c_tilde = self._h(mu + w1_bytes_tilde, 32)
                c = self._sample_in_ball(c_tilde)
                c.to_ntt()
                z = y + s1.scale(c).from_ntt()
                if z.check_norm_bound(self.gamma_1 - self.beta):
                    continue
                
                w0_minus_cs2 = w0 - s2.scale(c).from_ntt()
                if w0_minus_cs2.check_norm_bound(self.gamma_2 - self.beta):
                    continue
                
                c_t0 = t0.scale(c).from_ntt()
                # c_t0.reduce_coefficents()
                if c_t0.check_norm_bound(self.gamma_2):
                    continue
                
                w0_minus_cs2_plus_ct0 = w0_minus_cs2 + c_t0
                h = self._make_hint(w0_minus_cs2_plus_ct0, w1, alpha)            
                if self._sum_hint(h) > self.omega:
                    continue
                
                self.sk_params[sk_bytes]['precomputed'].remove((w0, w1, w1_bytes, y, kappa))
                return self._pack_sig(c_tilde, z, h), 0, y
            
        A = self._expandA(rho, is_ntt=True)
        u = self._h(tr, 64)
        pre_len = len(self.sk_params[sk_bytes]['precomputed'])
        if pre_len > 0:
            _, _, _, _, kappa = self.sk_params[sk_bytes]['precomputed'][pre_len - 1]
        else:
            kappa = 0
        rho_prime = self._h(K + u, 64)
        
        i = 0
        while True:
            i = i + 1
            y = self._expandMask(rho_prime, kappa)
            y_hat = y.copy_to_ntt()
            
            kappa += self.l
            
            w  = (A @ y_hat).from_ntt()
            w1, w0 = w.decompose(alpha)
            
            w1_bytes = w1.bit_pack_w(self.gamma_2) 

            if (w0, w1, w1_bytes, y) not in self.sk_params[sk_bytes]['precomputed']:
                self.sk_params[sk_bytes]['precomputed'].append((w0, w1, w1_bytes, y, kappa))
            
            w1_bytes_tilde = self._h(m + w1_bytes, 64)

            c_tilde = self._h(mu + w1_bytes_tilde, 32) 
            c = self._sample_in_ball(c_tilde)
            c.to_ntt()
            
            z = y + s1.scale(c).from_ntt() 
            if z.check_norm_bound(self.gamma_1 - self.beta):
                continue

            w0_minus_cs2 = w0 - s2.scale(c).from_ntt()
            if w0_minus_cs2.check_norm_bound(self.gamma_2 - self.beta): 
                continue
            
            c_t0 = t0.scale(c).from_ntt()
            # c_t0.reduce_coefficents()

            if c_t0.check_norm_bound(self.gamma_2):
                continue
            
            w0_minus_cs2_plus_ct0 = w0_minus_cs2 + c_t0
            
            h = self._make_hint(w0_minus_cs2_plus_ct0, w1, alpha)            

            if self._sum_hint(h) > self.omega:
                continue
            
            
            self.sk_params[sk_bytes]['precomputed'].remove((w0, w1, w1_bytes, y, kappa))
            return self._pack_sig(c_tilde, z, h), i, y
        
    def sign(self, sk_bytes, m):
        # unpack the secret key
        rho, K, tr, s1, s2, t0 = self._unpack_sk(sk_bytes)
        
        # Generate matrix A ∈ R^(kxl)
        A = self._expandA(rho, is_ntt=True)
        
        # Set seeds and nonce (kappa)
        mu = self._h(tr + m, 64)
        kappa = 0
        rho_prime = self._h(K + mu, 64)
        
        # Precompute NTT representation
        s1.to_ntt()
        s2.to_ntt()
        t0.to_ntt()
        
        alpha = self.gamma_2 << 1
        i = 0
        while True:
            i = i+1
            y = self._expandMask(rho_prime, kappa)
            y_hat = y.copy_to_ntt()
            
            # increment the nonce
            kappa += self.l
            
            w  = (A @ y_hat).from_ntt()

            # Extract out both the high and low bits
            w1, w0 = w.decompose(alpha)
            
            # Create challenge polynomial
            w1_bytes = w1.bit_pack_w(self.gamma_2)
            c_tilde = self._h(mu + w1_bytes, 32)
            c = self._sample_in_ball(c_tilde)
            
            # Store c in NTT form
            c.to_ntt()
            
            z = y + s1.scale(c).from_ntt()
            if z.check_norm_bound(self.gamma_1 - self.beta):
                continue

            w0_minus_cs2 = w0 - s2.scale(c).from_ntt()
            if w0_minus_cs2.check_norm_bound(self.gamma_2 - self.beta):
                continue
            
            c_t0 = t0.scale(c).from_ntt()
            # c_t0.reduce_coefficents()

            if c_t0.check_norm_bound(self.gamma_2):
                continue
            
            w0_minus_cs2_plus_ct0 = w0_minus_cs2 + c_t0
            
            h = self._make_hint(w0_minus_cs2_plus_ct0, w1, alpha)            

            if self._sum_hint(h) > self.omega:
                continue
            
            return self._pack_sig(c_tilde, z, h), i, y

                
        
    def verify(self, pk_bytes, m, sig_bytes):
        rho, t1 = self._unpack_pk(pk_bytes)
        c_tilde, z, h = self._unpack_sig(sig_bytes)
        
        if self._sum_hint(h) > self.omega:
            return False
            
        if z.check_norm_bound(self.gamma_1 - self.beta):
            return False
            
        A = self._expandA(rho, is_ntt=True)
        
        tr = self._h(pk_bytes, 32)
        mu = self._h(tr + m, 64)
        c = self._sample_in_ball(c_tilde)
        
        # Convert to NTT for computation
        c.to_ntt()
        z.to_ntt()
        
        t1 = t1.scale(1 << self.d)
        t1.to_ntt()
        
        Az_minus_ct1 = (A @ z) - t1.scale(c)
        Az_minus_ct1.from_ntt()
        
        w_prime = self._use_hint(h, Az_minus_ct1, 2*self.gamma_2)
        w_prime_bytes = w_prime.bit_pack_w(self.gamma_2)
        
        return c_tilde == self._h(mu + w_prime_bytes, 32)
    
    def verify_precomputed(self, pk_bytes, m, sig_bytes):
        rho, t1 = self._unpack_pk(pk_bytes)
        c_tilde, z, h = self._unpack_sig(sig_bytes)
        
        if self._sum_hint(h) > self.omega:
            return False
            
        if z.check_norm_bound(self.gamma_1 - self.beta):
            return False
            
        A = self._expandA(rho, is_ntt=True)
        
        tr = self._h(pk_bytes, 32)
        mu = self._h(tr + m, 64)
        c = self._sample_in_ball(c_tilde)
        
        # Convert to NTT for computation
        c.to_ntt()
        z.to_ntt()
        
        t1 = t1.scale(1 << self.d)
        t1.to_ntt()
        
        Az_minus_ct1 = (A @ z) - t1.scale(c)
        Az_minus_ct1.from_ntt()
        
        w_prime = self._use_hint(h, Az_minus_ct1, 2*self.gamma_2)
        w_prime_bytes = w_prime.bit_pack_w(self.gamma_2)
        w_prime_bytes_tilde = self._h(m + w_prime_bytes, 64)
        
        return c_tilde == self._h(mu + w_prime_bytes_tilde, 32)
        
Dilithium2 = Dilithium(DEFAULT_PARAMETERS["dilithium2"])
Dilithium3 = Dilithium(DEFAULT_PARAMETERS["dilithium3"])
Dilithium4 = Dilithium(DEFAULT_PARAMETERS["dilithium4"])
Dilithium5 = Dilithium(DEFAULT_PARAMETERS["dilithium5"])